import { ApiClient, ApiError } from "./api.js";
import {
  actionButton,
  badge,
  detailField,
  element,
  field,
  inputControl,
  loadingState,
  pager,
  panel,
  selectControl,
  stateCard,
  table,
  textElement,
} from "./components.js";
import { compactId, filterRecords, formatTimestamp, summaryText } from "./model.js";

const viewRoot = document.querySelector("#app-view");
const pageTitle = document.querySelector("#page-title");
const pageEyebrow = document.querySelector("#page-eyebrow");
const connectionPill = document.querySelector("#connection-pill");
const connectButton = document.querySelector("#connect-button");
const disconnectButton = document.querySelector("#disconnect-button");
const sidebar = document.querySelector("#sidebar");
const mobileMenu = document.querySelector("#mobile-menu");

const PAGE_INFO = {
  overview: {
    title: "Overview",
    eyebrow: "SECURITY OPERATIONS",
    description: "A live summary of alerts, incidents, and normalized events available to your API role.",
  },
  alerts: {
    title: "Alerts",
    eyebrow: "DETECTION OUTPUT",
    description: "Review persisted alerts from the local detection pipeline. Search is limited to the page currently loaded from the API.",
  },
  incidents: {
    title: "Incidents",
    eyebrow: "CASE MANAGEMENT",
    description: "Review incident status, severity, timestamps, and linked alert and event references.",
  },
  events: {
    title: "Events",
    eyebrow: "NORMALIZED TELEMETRY",
    description: "Inspect normalized security events stored by the local ingestion pipeline.",
  },
  health: {
    title: "System health",
    eyebrow: "SERVICE STATUS",
    description: "Check the existing API health route and see which local integration modules are included in this build.",
  },
  audit: {
    title: "Audit history",
    eyebrow: "ADMINISTRATION",
    description: "Review paginated security and incident actions recorded by the local API.",
  },
};

const PAGE_SIZE = 25;
const state = {
  api: null,
  role: null,
  apiBase: "http://127.0.0.1:8000",
  view: "overview",
  generation: 0,
  offsets: { alerts: 0, incidents: 0, events: 0, audit: 0 },
  noteOffset: 0,
  noteIncidentId: null,
  filters: {
    alerts: { severity: "", rule_id: "", source: "", search: "" },
    incidents: { status: "", severity: "", search: "" },
    events: { event_type: "", source_ip: "", severity: "", search: "" },
    audit: { action: "", resource_type: "", resource_id: "" },
  },
};

function setConnection(connected) {
  connectionPill.classList.toggle("is-connected", connected);
  const label = connectionPill.querySelector("span:last-child");
  if (label) label.textContent = connected ? "API connected" : "Not connected";
  connectButton.textContent = connected ? "Change account" : "Sign in";
  disconnectButton.textContent = "Sign out";
  disconnectButton.hidden = !connected;
}

function setHeading(view) {
  const info = PAGE_INFO[view] || PAGE_INFO.overview;
  pageTitle.textContent = info.title;
  pageEyebrow.textContent = info.eyebrow;
}

function updateNavigation() {
  for (const button of document.querySelectorAll("[data-view]")) {
    const restricted = button.dataset.view === "audit" && state.role !== "admin";
    button.hidden = restricted;
    const active = button.dataset.view === state.view;
    button.classList.toggle("is-active", active);
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
}

function pageIntro(view) {
  const info = PAGE_INFO[view];
  const intro = element("div", "page-intro");
  const copy = element("div");
  copy.append(textElement("h2", info.title), textElement("p", info.description));
  intro.append(copy);
  return intro;
}

function setBusy(busy) {
  viewRoot.setAttribute("aria-busy", String(busy));
}

function showConnectError(message) {
  state.api = null;
  setConnection(false);
  renderConnect(message);
}

function handleError(container, error, retry, generation = state.generation) {
  if (generation !== state.generation) return;
  if (error instanceof ApiError && error.status === 401) {
    showConnectError(error.message);
    return;
  }
  setBusy(false);
  const denied = error instanceof ApiError && error.status === 403;
  const title = denied ? "Access restricted" : "Could not load data";
  const message = denied
    ? "Your authenticated API role is not permitted to view this section. Contact the local administrator if you need access."
    : error instanceof Error ? error.message : "The local API returned an unexpected error.";
  const action = denied ? null : actionButton("Try again", retry, "button button-secondary button-small");
  container.replaceChildren(stateCard(title, message, { error: !denied, action }));
}

function renderConnect(message = "", mode = "account") {
  state.generation += 1;
  state.api = null;
  state.role = null;
  state.view = "overview";
  setHeading("overview");
  updateNavigation();
  viewRoot.setAttribute("aria-busy", "false");
  setConnection(false);

  const wrap = element("div", "connect-wrap");
  const card = element("section", "connect-card");
  const symbol = textElement("span", "N", "connect-symbol");
  symbol.setAttribute("aria-hidden", "true");
  card.append(symbol, textElement("h2", "Sign in to your local SOC"));
  card.append(textElement(
    "p",
    "Sign in with your SOC account. Your password is sent only to the loopback API over this local connection and is not retained by the dashboard.",
  ));

  const form = element("form", "connect-form");
  const apiInput = inputControl("api-address", "url", "http://127.0.0.1:8000", state.apiBase);
  apiInput.autocomplete = "url";
  apiInput.required = true;
  form.append(field("Local API address", apiInput));
  const credentialInput = mode === "account"
    ? inputControl("login-password", "password", "Password")
    : inputControl("api-token", "password", "Paste the configured bearer token");
  credentialInput.autocomplete = mode === "account" ? "current-password" : "off";
  credentialInput.required = true;
  credentialInput.spellcheck = false;
  if (mode === "account") {
    const usernameInput = inputControl("login-username", "text", "Username");
    usernameInput.autocomplete = "username";
    usernameInput.required = true;
    usernameInput.maxLength = 64;
    form.append(field("Username", usernameInput));
  } else {
    credentialInput.minLength = 16;
  }
  const submit = textElement("button", mode === "account" ? "Sign in" : "Connect with bearer", "button button-primary");
  submit.type = "submit";
  form.append(field(mode === "account" ? "Password" : "Configured bearer token", credentialInput));
  if (message) {
    const error = textElement("p", message, "connect-error");
    error.setAttribute("role", "alert");
    form.append(error);
  }
  form.append(submit);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    submit.textContent = mode === "account" ? "Signing in…" : "Connecting…";
    try {
      let candidate;
      let authenticatedRole = null;
      if (mode === "account") {
        const login = ApiClient.login(apiInput.value, {
          username: document.querySelector("#login-username").value,
          password: credentialInput.value,
        });
        // Keep the password only for the duration of request construction.
        credentialInput.value = "";
        const result = await login;
        candidate = result.client;
        authenticatedRole = result.role;
      } else {
        candidate = new ApiClient(apiInput.value, credentialInput.value);
        const health = await candidate.health();
        if (health?.status !== "ok") throw new ApiError(502, "The local API health check did not return an OK status.");
        // Alerts are readable by each configured role, so this verifies the
        // bearer without assuming analyst or administrator permissions.
        await candidate.listAlerts({ limit: 1, offset: 0 });
      }
      state.api = candidate;
      state.role = authenticatedRole;
      state.apiBase = candidate.baseUrl;
      credentialInput.value = "";
      setConnection(true);
      renderCurrent();
    } catch (error) {
      credentialInput.value = "";
      submit.disabled = false;
      submit.textContent = mode === "account" ? "Sign in" : "Connect with bearer";
      const messageText = error instanceof Error ? error.message : "Could not connect to the local API.";
      renderConnect(messageText, mode);
      document.querySelector(mode === "account" ? "#login-username" : "#api-token")?.focus();
    }
  });
  const methodSwitch = textElement(
    "button",
    mode === "account" ? "Use an existing configured bearer token" : "Sign in with username and password",
    "auth-method-switch",
  );
  methodSwitch.type = "button";
  methodSwitch.addEventListener("click", () => renderConnect("", mode === "account" ? "token" : "account"));
  card.append(form, textElement(
    "p",
    "Tokens stay in this tab’s memory and are cleared on sign-out, reload, or when the API rejects an expired or revoked token. For browser access, allow this exact dashboard origin in SOC_CORS_ORIGINS. Keep the backend bound to 127.0.0.1.",
    "connect-hint",
  ));
  card.append(methodSwitch);
  wrap.append(card);
  viewRoot.replaceChildren(wrap);
}

async function signOut() {
  const current = state.api;
  if (!current) {
    renderConnect("Your local session has been cleared.");
    return;
  }
  disconnectButton.disabled = true;
  connectButton.disabled = true;
  disconnectButton.textContent = "Signing out…";
  let notice;
  try {
    await current.logout();
    notice = "Signed out. The API revoked this bearer token.";
  } catch (error) {
    notice = error instanceof ApiError && error.status === 401
      ? "Signed out. The API reports that this session is already expired or revoked."
      : "Signed out on this tab, but the API could not confirm revocation. Check the local API and ask an administrator to revoke this token if needed.";
  } finally {
    if (state.api === current) state.api = null;
    state.role = null;
    setConnection(false);
    connectButton.disabled = false;
    disconnectButton.disabled = false;
    disconnectButton.textContent = "Sign out";
    renderConnect(notice);
  }
}

function metricCard(title, glyph, note) {
  const card = element("article", "metric-card");
  const top = element("div", "metric-top");
  top.append(textElement("span", title));
  top.append(textElement("span", glyph, "metric-glyph"));
  const value = textElement("div", "…", "metric-value");
  value.setAttribute("aria-live", "polite");
  card.append(top, value, textElement("div", note, "metric-note"));
  return { card, value };
}

function metricFailure(metric, error, permissionHint) {
  metric.value.textContent = error.status === 403 ? "Restricted" : "—";
  metric.value.classList.toggle("is-restricted", error.status === 403);
  const note = metric.card.querySelector(".metric-note");
  note.textContent = error.status === 403 ? permissionHint : "Data unavailable";
}

function sourceCell(ip, sources = [], destinationIp = null) {
  const wrapper = element("span");
  wrapper.append(textElement("span", `Source: ${ip || "IP unavailable"}`, "table-primary"));
  if (destinationIp) {
    wrapper.append(textElement("span", `Destination: ${destinationIp}`, "table-secondary table-mono"));
  }
  if (Array.isArray(sources) && sources.length) {
    wrapper.append(textElement("span", `Sources: ${sources.join(", ")}`, "table-secondary"));
  }
  return wrapper;
}

function eventColumns(onDetail = null) {
  const columns = [
    { label: "Timestamp", render: (item) => textElement("span", formatTimestamp(item.timestamp), "table-mono") },
    {
      label: "Event type",
      render: (item) => {
        const value = element("span");
        value.append(textElement("span", item.event_type, "table-primary"));
        if (item.source) value.append(textElement("span", item.source, "table-secondary"));
        return value;
      },
    },
    { label: "Source IP", render: (item) => textElement("span", item.source_ip || "—", "table-mono") },
    { label: "Severity", render: (item) => badge(item.severity || "unknown", item.severity || "unknown") },
    { label: "Details", render: (item) => textElement("span", summaryText(item.details), "truncate") },
  ];
  if (onDetail) {
    columns.push({
      label: "",
      render: (item) => actionButton("View", () => onDetail(item), "button button-quiet button-small"),
    });
  }
  return columns;
}

async function renderOverview(generation) {
  const intro = pageIntro("overview");
  const metricGrid = element("div", "overview-grid");
  const totalAlerts = metricCard("Total alerts", "AL", "All stored alert records");
  const criticalAlerts = metricCard("Critical alerts", "CR", "Critical severity");
  const openIncidents = metricCard("Open incidents", "IN", "Awaiting investigation");
  metricGrid.append(totalAlerts.card, criticalAlerts.card, openIncidents.card);

  const lower = element("div", "overview-lower");
  const recentPanel = panel("Recent events", "Latest normalized records available to your role");
  recentPanel.body.replaceChildren(loadingState());
  const systemPanel = panel("Platform snapshot", "Current API and local build capabilities");
  const summary = element("div", "system-summary");
  const apiLine = element("div", "summary-line");
  apiLine.append(textElement("span", "API connection"), textElement("span", "Connected", "summary-state"));
  const eveLine = element("div", "summary-line");
  eveLine.append(textElement("span", "Suricata EVE reader"), textElement("span", "Available", "summary-state"));
  const note = textElement("p", "The reader processes local EVE JSONL files. This API does not report whether Suricata is running.", "summary-note");
  summary.append(apiLine, eveLine, note);
  systemPanel.body.replaceChildren(summary);
  lower.append(recentPanel.wrapper, systemPanel.wrapper);
  viewRoot.replaceChildren(intro, metricGrid, lower);

  const api = state.api;
  const requests = await Promise.all([
    api.listAlerts({ limit: 1, offset: 0 }),
    api.listAlerts({ limit: 1, offset: 0, severity: "critical" }),
    api.listIncidents({ limit: 1, offset: 0, status: "open" }),
    api.listEvents({ limit: 5, offset: 0 }),
  ].map(async (promise) => {
    try { return { value: await promise }; }
    catch (error) { return { error }; }
  }));
  if (generation !== state.generation || api !== state.api) return;
  const all401 = requests.find((result) => result.error?.status === 401);
  if (all401) {
    showConnectError(all401.error.message);
    return;
  }
  for (const [index, metric] of [[0, totalAlerts], [1, criticalAlerts], [2, openIncidents]]) {
    const result = requests[index];
    if (result.error) {
      metricFailure(metric, result.error, "Requires analyst or admin role");
    } else {
      metric.value.textContent = Number(result.value.total || 0).toLocaleString();
    }
  }
  const eventsResult = requests[3];
  if (eventsResult.error) {
    recentPanel.body.replaceChildren(stateCard(
      eventsResult.error.status === 403 ? "Access restricted" : "Events unavailable",
      eventsResult.error.status === 403
        ? "Recent events require an analyst or administrator role."
        : eventsResult.error.message,
      { error: eventsResult.error.status !== 403 },
    ));
  } else if (!eventsResult.value.items.length) {
    recentPanel.body.replaceChildren(stateCard("No events yet", "Normalized events will appear after the local ingestion pipeline stores records."));
  } else {
    recentPanel.body.replaceChildren(table(eventColumns(), eventsResult.value.items, "No event records."));
  }
  setBusy(false);
}

function buildToolbar(fields, onSubmit, note = "") {
  const form = element("form", "toolbar");
  for (const item of fields) form.append(item);
  const apply = textElement("button", "Apply filters", "button button-secondary");
  apply.type = "submit";
  form.append(apply);
  if (note) form.append(textElement("p", note, "toolbar-note"));
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    onSubmit();
  });
  return form;
}

function alertSearchFields(item) {
  return [
    item.alert_id,
    item.rule_id,
    item.rule_name,
    item.description,
    item.source_ip,
    destinationIpFromEvidence(item.evidence),
    ...(item.sources || []),
  ];
}

function destinationIpFromEvidence(evidence) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) return null;
  for (const key of ["dest_ip", "destination_ip"]) {
    const value = evidence[key];
    if (typeof value === "string" && value.trim()) return value;
  }
  return null;
}

async function createIncidentFromAlert(detail, host, api, generation, button) {
  button.disabled = true;
  button.textContent = "Creating incident…";
  try {
    await api.createIncident({
      title: String(detail.rule_name || "Alert investigation").slice(0, 200),
      description: String(detail.description || "").slice(0, 10_000),
      severity: detail.severity,
      alert_ids: [detail.alert_id],
      supporting_event_refs: detail.supporting_event_refs || [],
    });
    if (generation !== state.generation || api !== state.api) return;
    state.view = "incidents";
    state.offsets.incidents = 0;
    state.filters.incidents = { status: "open", severity: "", search: "" };
    renderCurrent();
  } catch (error) {
    handleError(host, error, () => showAlertDetails(detail, host, api, generation), generation);
  }
}

async function showAlertDetails(alert, host, api, generation) {
  host.replaceChildren(loadingState("Loading alert details…"));
  try {
    const detail = await api.getAlert(alert.alert_id);
    if (generation !== state.generation || api !== state.api) return;
    const card = element("section", "detail-card");
    const heading = element("div", "detail-heading");
    heading.append(textElement("h3", detail.rule_name || "Alert details"));
    heading.append(badge(detail.severity || "unknown", detail.severity || "unknown"));
    const grid = element("dl", "detail-grid");
    for (const [label, value] of [
      ["Alert identifier", detail.alert_id],
      ["Rule", `${detail.rule_id} · ${detail.rule_name}`],
      ["Timestamp", formatTimestamp(detail.event_timestamp)],
      ["Source IP", detail.source_ip || "—"],
      ["Destination IP", destinationIpFromEvidence(detail.evidence) || "Not provided by this alert"],
      ["Sources", (detail.sources || []).join(" · ") || "—"],
      ["Workflow status", "Not tracked on alert records; linked incidents carry investigation status."],
      ["Description", detail.description],
      ["Supporting event references", (detail.supporting_event_refs || []).join("\n") || "—"],
      ["Evidence", JSON.stringify(detail.evidence ?? {}, null, 2)],
    ]) grid.append(detailField(label, value));
    card.append(heading, grid);
    if (state.role !== "reader") {
      const actions = element("div", "detail-actions");
      const createButton = textElement("button", "Create linked incident", "button button-primary button-small");
      createButton.type = "button";
      createButton.addEventListener("click", () => {
        void createIncidentFromAlert(detail, host, api, generation, createButton);
      });
      actions.append(createButton);
      card.append(actions);
    }
    host.replaceChildren(card);
  } catch (error) {
    handleError(host, error, () => showAlertDetails(alert, host, api, generation), generation);
  }
}

async function renderAlerts(generation) {
  const intro = pageIntro("alerts");
  const filters = state.filters.alerts;
  const search = inputControl("alert-search", "search", "Search this page", filters.search);
  const severity = selectControl("alert-severity", [
    { value: "", label: "All severities" },
    { value: "critical", label: "Critical" },
    { value: "high", label: "High" },
    { value: "medium", label: "Medium" },
    { value: "low", label: "Low" },
    { value: "informational", label: "Informational" },
  ], filters.severity);
  const rule = inputControl("alert-rule", "search", "Filter by rule ID", filters.rule_id);
  const source = inputControl("alert-source", "search", "Filter by source IP/name", filters.source);
  const status = selectControl("alert-status", [{ value: "", label: "Alert status not tracked" }]);
  status.disabled = true;
  const toolbar = buildToolbar([
    field("Search loaded page", search, "field field-wide"),
    field("Severity", severity),
    field("Rule", rule),
    field("Source", source),
    field("Status", status),
  ], () => {
    state.filters.alerts = {
      severity: severity.value,
      rule_id: rule.value.trim(),
      source: source.value.trim(),
      search: search.value.trim(),
    };
    state.offsets.alerts = 0;
    renderCurrent();
  }, "Search and source filters scan the records on this page. Severity and rule filters use the API. Investigation status belongs to a linked incident; the alert API does not store alert status.");
  const results = element("section", "panel");
  const heading = element("div", "panel-heading");
  heading.append(textElement("h3", "Stored alerts"), textElement("p", "Live results from GET /api/v1/alerts"));
  results.append(heading);
  const body = element("div");
  body.replaceChildren(loadingState());
  results.append(body);
  const details = element("div");
  viewRoot.replaceChildren(intro, toolbar, results, details);
  setBusy(true);

  const api = state.api;
  try {
    const page = await api.listAlerts({
      limit: PAGE_SIZE,
      offset: state.offsets.alerts,
      severity: filters.severity || undefined,
      rule_id: filters.rule_id || undefined,
    });
    if (generation !== state.generation || api !== state.api) return;
    function paintRows() {
      const sourceNeedle = source.value.trim().toLocaleLowerCase();
      const sourceMatched = page.items.filter((item) =>
        [item.source_ip, destinationIpFromEvidence(item.evidence), ...(item.sources || [])]
          .some((value) => String(value || "").toLocaleLowerCase().includes(sourceNeedle)));
      const visible = filterRecords(sourceMatched, search.value, alertSearchFields);
      const columns = [
        { label: "Severity", render: (item) => badge(item.severity, item.severity) },
        { label: "Alert / rule", render: (item) => {
          const value = element("span");
          value.append(textElement("span", item.rule_name, "table-primary"));
          value.append(textElement("span", item.rule_id, "table-secondary table-mono"));
          return value;
        } },
        { label: "Detection", render: (item) => textElement("span", item.description, "truncate") },
        { label: "IP addresses / sources", render: (item) => sourceCell(
          item.source_ip,
          item.sources,
          destinationIpFromEvidence(item.evidence),
        ) },
        { label: "Timestamp", render: (item) => textElement("span", formatTimestamp(item.event_timestamp), "table-mono") },
        { label: "Status", render: () => badge("Not tracked", "unavailable") },
        { label: "", render: (item) => actionButton("Details", () => showAlertDetails(item, details, api, generation)) },
      ];
      body.replaceChildren(table(columns, visible, search.value ? "No alerts on this page match the search." : "No alerts match these API filters."));
      body.append(pager({
        offset: state.offsets.alerts,
        total: page.total,
        limit: PAGE_SIZE,
        onChange: (offset) => { state.offsets.alerts = offset; renderCurrent(); },
      }));
    }
    search.addEventListener("input", paintRows);
    paintRows();
    setBusy(false);
  } catch (error) {
    handleError(body, error, () => renderCurrent(), generation);
  }
}

function incidentSearchFields(item) {
  return [item.incident_id, item.title, item.description, item.status, item.severity, ...(item.alert_ids || []), ...(item.supporting_event_refs || [])];
}

async function showIncidentDetails(incident, host, api, generation) {
  if (state.noteIncidentId !== incident.incident_id) {
    state.noteIncidentId = incident.incident_id;
    state.noteOffset = 0;
  }
  host.replaceChildren(loadingState("Loading incident details…"));
  try {
    const detail = await api.getIncident(incident.incident_id);
    if (generation !== state.generation || api !== state.api) return;
    renderIncidentDetails(detail, host, api, generation);
  } catch (error) {
    handleError(host, error, () => showIncidentDetails(incident, host, api, generation), generation);
  }
}

const INCIDENT_TRANSITIONS = {
  open: ["investigating"],
  investigating: ["open", "resolved"],
  resolved: ["investigating", "closed"],
  closed: [],
};

const TRANSITION_LABELS = {
  investigating: "Start investigation",
  resolved: "Resolve incident",
  open: "Reopen incident",
  closed: "Close incident",
};

async function applyIncidentTransition(detail, target, host, api, generation, button) {
  button.disabled = true;
  button.textContent = "Updating status…";
  try {
    const updated = await api.transitionIncident(detail.incident_id, target);
    if (generation !== state.generation || api !== state.api) return;
    renderIncidentDetails(updated, host, api, generation);
  } catch (error) {
    handleError(host, error, () => showIncidentDetails(detail, host, api, generation), generation);
  }
}

function renderIncidentDetails(detail, host, api, generation) {
  const card = element("section", "detail-card");
  const heading = element("div", "detail-heading");
  heading.append(textElement("h3", detail.title));
  heading.append(badge(detail.status, detail.status));
  const grid = element("dl", "detail-grid");
  for (const [label, value] of [
    ["Incident identifier", detail.incident_id],
    ["Severity", detail.severity],
    ["Description", detail.description || "—"],
    ["Created", formatTimestamp(detail.created_at)],
    ["Updated", formatTimestamp(detail.updated_at)],
    ["Resolved", detail.resolved_at ? formatTimestamp(detail.resolved_at) : "Not resolved"],
    ["Closed", detail.closed_at ? formatTimestamp(detail.closed_at) : "Not closed"],
    ["Linked alert IDs", (detail.alert_ids || []).join("\n") || "—"],
    ["Supporting event references", (detail.supporting_event_refs || []).join("\n") || "—"],
  ]) grid.append(detailField(label, value));
  card.append(heading, grid);

  const validTransitions = INCIDENT_TRANSITIONS[detail.status] || [];
  const allowedTargets = state.role === "analyst"
    ? validTransitions.filter((target) => ["investigating", "resolved"].includes(target))
    : validTransitions;
  if (state.role !== "reader" && allowedTargets.length) {
    const actions = element("div", "detail-actions");
    for (const target of allowedTargets) {
      const button = textElement("button", TRANSITION_LABELS[target], "button button-secondary button-small");
      button.type = "button";
      button.addEventListener("click", () => {
        void applyIncidentTransition(detail, target, host, api, generation, button);
      });
      actions.append(button);
    }
    card.append(actions);
  }

  const notes = panel(
    "Investigation notes",
    "Append-only notes from GET /api/v1/incidents/{incident_id}/notes, shown oldest first.",
  );
  notes.body.replaceChildren(loadingState("Loading investigation notes…"));
  host.replaceChildren(card, notes.wrapper);

  if (state.role !== "analyst" && state.role !== "admin") {
    notes.body.replaceChildren(stateCard(
      "Access restricted",
      "Investigation notes are available to analysts and administrators.",
    ));
    return;
  }

  let noteTotal = 0;
  const feedback = textElement("p", "", "note-feedback");
  feedback.setAttribute("role", "status");
  const form = element("form", "note-form");
  const noteInput = element("textarea");
  noteInput.id = "incident-note-text";
  noteInput.rows = 4;
  noteInput.maxLength = 5000;
  noteInput.required = true;
  noteInput.placeholder = "Record investigation observations…";
  noteInput.setAttribute("aria-describedby", "incident-note-hint");
  form.append(field("Add investigation note", noteInput, "field note-field"));
  const noteHint = textElement("p", "Notes are append-only and visible to analysts and administrators.", "toolbar-note");
  noteHint.id = "incident-note-hint";
  form.append(noteHint);
  const submit = textElement("button", "Add note", "button button-primary button-small");
  submit.type = "submit";
  form.append(feedback, submit);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const noteText = noteInput.value;
    if (!noteText.trim()) {
      feedback.textContent = "Enter a note before submitting.";
      feedback.className = "note-feedback is-error";
      return;
    }
    submit.disabled = true;
    submit.textContent = "Saving note…";
    feedback.textContent = "";
    try {
      await api.appendIncidentNote(detail.incident_id, noteText);
      if (generation !== state.generation || api !== state.api) return;
      noteInput.value = "";
      feedback.textContent = "Note added.";
      feedback.className = "note-feedback is-success";
      // Notes are sorted oldest first by the API. Move to the page containing
      // the newly appended record, then reload the API page to confirm it.
      state.noteOffset = Math.floor(noteTotal / PAGE_SIZE) * PAGE_SIZE;
      await loadIncidentNotes(detail.incident_id, notes.body, api, generation, (page) => {
        noteTotal = page.total;
      });
    } catch (error) {
      if (generation !== state.generation || api !== state.api) return;
      if (error instanceof ApiError && error.status === 401) {
        handleError(notes.body, error, () => showIncidentDetails(detail, host, api, generation), generation);
      } else {
        feedback.textContent = error instanceof ApiError && error.status === 403
          ? "Your API role is not permitted to append notes to this incident."
          : `The note could not be confirmed. Refresh the note list before retrying. ${error instanceof Error ? error.message : ""}`.trim();
        feedback.className = "note-feedback is-error";
      }
    } finally {
      if (generation === state.generation && api === state.api) {
        submit.disabled = false;
        submit.textContent = "Add note";
      }
    }
  });
  notes.wrapper.append(form);
  void loadIncidentNotes(detail.incident_id, notes.body, api, generation, (page) => {
    noteTotal = page.total;
  });
}

function noteActor(note) {
  if (note.author_username) return `${note.author_username} · ${note.author_role}`;
  return `${note.author_role} · ${note.author_type}`;
}

async function loadIncidentNotes(incidentId, container, api, generation, onLoaded = () => {}) {
  container.replaceChildren(loadingState("Loading investigation notes…"));
  try {
    const page = await api.listIncidentNotes(incidentId, {
      limit: PAGE_SIZE,
      offset: state.noteOffset,
    });
    if (generation !== state.generation || api !== state.api) return null;
    onLoaded(page);
    if (!page.items.length) {
      container.replaceChildren(stateCard(
        "No investigation notes",
        "Append the first note when there is an observation to record.",
      ));
    } else {
      const list = element("ol", "note-list");
      for (const note of page.items) {
        const entry = element("li", "note-entry");
        const header = element("div", "note-entry-heading");
        header.append(textElement("span", noteActor(note), "table-primary"));
        header.append(textElement("time", formatTimestamp(note.created_at), "table-mono"));
        const content = textElement("p", note.note_text, "note-content");
        entry.append(header, content);
        list.append(entry);
      }
      container.replaceChildren(list);
      container.append(pager({
        offset: state.noteOffset,
        total: page.total,
        limit: PAGE_SIZE,
        onChange: (offset) => {
          state.noteOffset = offset;
          void loadIncidentNotes(incidentId, container, api, generation, onLoaded);
        },
      }));
    }
    return page;
  } catch (error) {
    handleError(container, error, () => loadIncidentNotes(incidentId, container, api, generation, onLoaded), generation);
    return null;
  }
}

async function renderIncidents(generation) {
  const intro = pageIntro("incidents");
  const filters = state.filters.incidents;
  const search = inputControl("incident-search", "search", "Search loaded incidents", filters.search);
  const status = selectControl("incident-status", [
    { value: "", label: "All statuses" },
    { value: "open", label: "Open" },
    { value: "investigating", label: "Investigating" },
    { value: "resolved", label: "Resolved" },
    { value: "closed", label: "Closed" },
  ], filters.status);
  const severity = selectControl("incident-severity", [
    { value: "", label: "All severities" },
    { value: "critical", label: "Critical" },
    { value: "high", label: "High" },
    { value: "medium", label: "Medium" },
    { value: "low", label: "Low" },
    { value: "informational", label: "Informational" },
  ], filters.severity);
  const toolbar = buildToolbar([
    field("Search loaded page", search, "field field-wide"),
    field("Status", status),
    field("Severity", severity),
  ], () => {
    state.filters.incidents = { status: status.value, severity: severity.value, search: search.value.trim() };
    state.offsets.incidents = 0;
    renderCurrent();
  });
  const results = element("section", "panel");
  const heading = element("div", "panel-heading");
  heading.append(textElement("h3", "Incident register"), textElement("p", "Live results from GET /api/v1/incidents"));
  results.append(heading);
  const body = element("div");
  body.replaceChildren(loadingState());
  results.append(body);
  const details = element("div");
  viewRoot.replaceChildren(intro, toolbar, results, details);
  setBusy(true);
  const api = state.api;
  try {
    const page = await api.listIncidents({
      limit: PAGE_SIZE,
      offset: state.offsets.incidents,
      status: filters.status || undefined,
      severity: filters.severity || undefined,
    });
    if (generation !== state.generation || api !== state.api) return;
    function paintRows() {
      const visible = filterRecords(page.items, search.value, incidentSearchFields);
      const columns = [
        { label: "Status", render: (item) => badge(item.status, item.status) },
        { label: "Incident", render: (item) => {
          const value = element("span");
          value.append(textElement("span", item.title, "table-primary"));
          value.append(textElement("span", compactId(item.incident_id), "table-secondary table-mono"));
          return value;
        } },
        { label: "Severity", render: (item) => badge(item.severity, item.severity) },
        { label: "Created", render: (item) => textElement("span", formatTimestamp(item.created_at), "table-mono") },
        { label: "Linked records", render: (item) => `${(item.alert_ids || []).length} alerts · ${(item.supporting_event_refs || []).length} events` },
        { label: "", render: (item) => actionButton("Details", () => showIncidentDetails(item, details, api, generation)) },
      ];
      body.replaceChildren(table(columns, visible, search.value ? "No incidents on this page match the search." : "No incidents match these API filters."));
      body.append(pager({
        offset: state.offsets.incidents,
        total: page.total,
        limit: PAGE_SIZE,
        onChange: (offset) => { state.offsets.incidents = offset; renderCurrent(); },
      }));
    }
    search.addEventListener("input", paintRows);
    paintRows();
    setBusy(false);
  } catch (error) {
    handleError(body, error, () => renderCurrent(), generation);
  }
}

function eventSearchFields(item) {
  return [item.event_id, item.timestamp, item.event_type, item.source, item.source_ip, item.severity, JSON.stringify(item.details ?? {})];
}

async function showEventDetails(eventRecord, host, api, generation) {
  host.replaceChildren(loadingState("Loading event details…"));
  try {
    const detail = await api.getEvent(eventRecord.event_id);
    if (generation !== state.generation || api !== state.api) return;
    const card = element("section", "detail-card");
    const heading = element("div", "detail-heading");
    heading.append(textElement("h3", detail.event_type));
    heading.append(badge(detail.severity || "unknown", detail.severity || "unknown"));
    const grid = element("dl", "detail-grid");
    for (const [label, value] of [
      ["Event identifier", detail.event_id],
      ["Timestamp", formatTimestamp(detail.timestamp)],
      ["Source", detail.source || "—"],
      ["Source IP", detail.source_ip || "—"],
      ["Complete normalized details", JSON.stringify(detail.details ?? {}, null, 2)],
    ]) grid.append(detailField(label, value));
    card.append(heading, grid);
    host.replaceChildren(card);
  } catch (error) {
    handleError(host, error, () => showEventDetails(eventRecord, host, api, generation), generation);
  }
}

async function renderEvents(generation) {
  const intro = pageIntro("events");
  const filters = state.filters.events;
  const search = inputControl("event-search", "search", "Search loaded events", filters.search);
  const eventType = inputControl("event-type", "search", "Event type", filters.event_type);
  const sourceIp = inputControl("event-source-ip", "search", "Source IP", filters.source_ip);
  const severity = selectControl("event-severity", [
    { value: "", label: "All severities" },
    { value: "critical", label: "Critical" },
    { value: "high", label: "High" },
    { value: "medium", label: "Medium" },
    { value: "low", label: "Low" },
    { value: "informational", label: "Informational" },
    { value: "unknown", label: "Unknown" },
  ], filters.severity);
  const toolbar = buildToolbar([
    field("Search loaded page", search, "field field-wide"),
    field("Event type", eventType),
    field("Source IP", sourceIp),
    field("Severity", severity),
  ], () => {
    state.filters.events = {
      event_type: eventType.value.trim(),
      source_ip: sourceIp.value.trim(),
      severity: severity.value,
      search: search.value.trim(),
    };
    state.offsets.events = 0;
    renderCurrent();
  });
  const results = element("section", "panel");
  const heading = element("div", "panel-heading");
  heading.append(textElement("h3", "Normalized events"), textElement("p", "Live results from GET /api/v1/events"));
  results.append(heading);
  const body = element("div");
  body.replaceChildren(loadingState());
  results.append(body);
  const details = element("div");
  viewRoot.replaceChildren(intro, toolbar, results, details);
  setBusy(true);
  const api = state.api;
  try {
    const page = await api.listEvents({
      limit: PAGE_SIZE,
      offset: state.offsets.events,
      event_type: filters.event_type || undefined,
      source_ip: filters.source_ip || undefined,
      severity: filters.severity || undefined,
    });
    if (generation !== state.generation || api !== state.api) return;
    function paintRows() {
      const visible = filterRecords(page.items, search.value, eventSearchFields);
      body.replaceChildren(table([
        { label: "Timestamp", render: (item) => textElement("span", formatTimestamp(item.timestamp), "table-mono") },
        { label: "Event type / source", render: (item) => {
          const value = element("span");
          value.append(textElement("span", item.event_type, "table-primary"));
          if (item.source) value.append(textElement("span", item.source, "table-secondary"));
          return value;
        } },
        { label: "Source IP", render: (item) => textElement("span", item.source_ip || "—", "table-mono") },
        { label: "Severity", render: (item) => badge(item.severity || "unknown", item.severity || "unknown") },
        { label: "Details", render: (item) => textElement("span", summaryText(item.details), "truncate") },
        { label: "", render: (item) => actionButton("Details", () => showEventDetails(item, details, api, generation)) },
      ], visible, search.value ? "No events on this page match the search." : "No normalized events are stored yet."));
      body.append(pager({
        offset: state.offsets.events,
        total: page.total,
        limit: PAGE_SIZE,
        onChange: (offset) => { state.offsets.events = offset; renderCurrent(); },
      }));
    }
    search.addEventListener("input", paintRows);
    paintRows();
    setBusy(false);
  } catch (error) {
    handleError(body, error, () => renderCurrent(), generation);
  }
}

function auditSummary(event) {
  if (event.action === "incident.create") return "Incident created.";
  if (event.action === "incident.update") return "Incident metadata updated.";
  if (event.action.startsWith("incident.transition.")) return "Incident status changed.";
  if (event.action === "incident.note.append") return "Investigation note appended; note text is not shown here.";
  if (event.action === "auth.login") return "Account authentication succeeded.";
  if (event.action === "auth.logout") return "Bearer credential revoked.";
  if (event.action.startsWith("user.")) return "Account administration action.";
  if (event.action.startsWith("token.")) return "Credential administration action; credential values are not shown.";
  return "Security-relevant action recorded.";
}

async function renderAuditHistory(generation) {
  const intro = pageIntro("audit");
  const body = element("div");
  const results = element("section", "panel");
  const heading = element("div", "panel-heading");
  heading.append(
    textElement("h3", "Persistent audit events"),
    textElement("p", "Read-only records from GET /api/v1/admin/audit-events. Newest records appear first."),
  );
  results.append(heading, body);

  if (state.role !== "admin") {
    viewRoot.replaceChildren(intro, stateCard(
      "Access restricted",
      "Audit history is available to administrators only.",
    ));
    setBusy(false);
    return;
  }

  const filters = state.filters.audit;
  const action = inputControl("audit-action", "search", "Exact action", filters.action);
  const resourceType = inputControl("audit-resource-type", "search", "Exact resource type", filters.resource_type);
  const resourceId = inputControl("audit-resource-id", "search", "Exact resource ID", filters.resource_id);
  const toolbar = buildToolbar([
    field("Action (exact)", action),
    field("Resource type (exact)", resourceType),
    field("Resource ID (exact)", resourceId),
  ], () => {
    state.filters.audit = {
      action: action.value.trim(),
      resource_type: resourceType.value.trim(),
      resource_id: resourceId.value.trim(),
    };
    state.offsets.audit = 0;
    renderCurrent();
  }, "These exact-match filters are supported by the audit API. Audit change payloads and token resource identifiers are not displayed.");

  body.replaceChildren(loadingState());
  viewRoot.replaceChildren(intro, toolbar, results);
  setBusy(true);
  const api = state.api;
  try {
    const page = await api.listAuditEvents({
      limit: PAGE_SIZE,
      offset: state.offsets.audit,
      action: filters.action || undefined,
      resource_type: filters.resource_type || undefined,
      resource_id: filters.resource_id || undefined,
    });
    if (generation !== state.generation || api !== state.api) return;
    const rows = page.items.map((item) => ({
      occurred: textElement("time", formatTimestamp(item.occurred_at), "table-mono"),
      actor: item.actor_username
        ? `${item.actor_username} · ${item.actor_role}`
        : `${item.actor_role} · ${item.actor_type}`,
      action: item.action,
      resource: item.resource_type === "api_token"
        ? "API token (identifier withheld)"
        : item.resource_id
          ? `${item.resource_type} · ${compactId(item.resource_id)}`
          : item.resource_type,
      summary: auditSummary(item),
    }));
    body.replaceChildren(table([
      { label: "When", render: (item) => item.occurred },
      { label: "Actor", render: (item) => item.actor },
      { label: "Action / resource", render: (item) => {
        const value = element("span");
        value.append(textElement("span", item.action, "table-primary"));
        value.append(textElement("span", item.resource, "table-secondary"));
        return value;
      } },
      { label: "Summary", render: (item) => item.summary },
    ], rows, "No audit events match these filters."));
    body.append(pager({
      offset: state.offsets.audit,
      total: page.total,
      limit: PAGE_SIZE,
      onChange: (offset) => { state.offsets.audit = offset; renderCurrent(); },
    }));
    setBusy(false);
  } catch (error) {
    handleError(body, error, () => renderCurrent(), generation);
  }
}

function healthCard(title, description, stateLabel, stateClass) {
  const card = element("article", "health-card");
  card.append(textElement("h3", title), textElement("p", description));
  card.append(textElement("span", stateLabel, `health-status ${stateClass}`));
  return card;
}

async function renderHealth(generation) {
  const intro = pageIntro("health");
  intro.append(actionButton("Refresh health check", () => renderCurrent(), "button button-secondary"));
  const grid = element("div", "health-grid");
  const apiCard = healthCard("FastAPI service", "GET /api/v1/health reports whether the local API process is responding.", "Checking…", "health-pending");
  const statusText = apiCard.querySelector(".health-status");
  const suricataCard = healthCard(
    "Suricata EVE JSON reader",
    "A passive local JSONL reader is included. It does not start Suricata or report live sensor state.",
    "Module available",
    "health-good",
  );
  const intelCard = healthCard(
    "Threat intelligence providers",
    "No provider or live enrichment status is exposed by the current backend.",
    "Not configured in this build",
    "health-muted",
  );
  const detailCard = healthCard(
    "Integration runtime status",
    "The existing API has no integration-status route. Live connection state cannot be verified here.",
    "Not reported by API",
    "health-pending",
  );
  grid.append(apiCard, suricataCard, intelCard, detailCard);
  const disclaimer = textElement(
    "p",
    "The integration labels above describe local code capabilities, not active network connections. This dashboard uses only the API routes already present in the backend.",
    "health-disclaimer",
  );
  viewRoot.replaceChildren(intro, grid, disclaimer);
  setBusy(true);
  try {
    const health = await state.api.health();
    if (generation !== state.generation) return;
    if (health?.status === "ok") {
      statusText.textContent = "Responding";
      statusText.className = "health-status health-good";
    } else {
      statusText.textContent = "Unexpected response";
      statusText.className = "health-status health-pending";
    }
  } catch (error) {
    if (generation !== state.generation) return;
    statusText.textContent = error instanceof Error ? error.message : "Unavailable";
    statusText.className = "health-status health-pending";
  }
  setBusy(false);
}

function renderCurrent() {
  state.generation += 1;
  const generation = state.generation;
  setHeading(state.view);
  updateNavigation();
  sidebar.classList.remove("is-open");
  mobileMenu.setAttribute("aria-expanded", "false");
  if (!state.api) {
    renderConnect();
    return;
  }
  setBusy(true);
  if (state.view === "overview") renderOverview(generation);
  else if (state.view === "alerts") renderAlerts(generation);
  else if (state.view === "incidents") renderIncidents(generation);
  else if (state.view === "events") renderEvents(generation);
  else if (state.view === "health") renderHealth(generation);
  else if (state.view === "audit") renderAuditHistory(generation);
}

document.querySelectorAll("[data-view]").forEach((button) => {
  button.addEventListener("click", () => {
    state.view = button.dataset.view;
    renderCurrent();
  });
});

connectButton.addEventListener("click", () => {
  if (state.api) void signOut();
  else renderConnect();
});
disconnectButton.addEventListener("click", () => void signOut());
mobileMenu.addEventListener("click", () => {
  const open = sidebar.classList.toggle("is-open");
  mobileMenu.setAttribute("aria-expanded", String(open));
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    sidebar.classList.remove("is-open");
    mobileMenu.setAttribute("aria-expanded", "false");
  }
});

setConnection(false);
renderConnect();
