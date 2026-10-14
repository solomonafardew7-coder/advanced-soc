/** DOM helpers. Untrusted API values enter the UI only through textContent. */

export function element(tagName, className = "") {
  const item = document.createElement(tagName);
  if (className) item.className = className;
  return item;
}

export function textElement(tagName, value, className = "") {
  const item = element(tagName, className);
  item.textContent = value === null || value === undefined ? "—" : String(value);
  return item;
}

export function appendText(parent, tagName, value, className = "") {
  const item = textElement(tagName, value, className);
  parent.append(item);
  return item;
}

export function actionButton(label, onClick, className = "button button-quiet button-small") {
  const button = textElement("button", label, className);
  button.type = "button";
  button.addEventListener("click", onClick);
  return button;
}

export function badge(label, kind = "neutral") {
  const allowed = new Set([
    "critical", "high", "medium", "low", "informational", "unknown",
    "open", "investigating", "resolved", "closed", "unavailable",
  ]);
  const safeKind = allowed.has(kind) ? kind : "unknown";
  const type = ["critical", "high", "medium", "low", "informational", "unknown"].includes(safeKind)
    ? `severity-${safeKind}`
    : safeKind === "unavailable" ? "status-unavailable" : `status-${safeKind}`;
  return textElement("span", label, `severity-badge ${type}`);
}

export function loadingState(message = "Loading live data from the local API…") {
  const state = element("div", "loading-state");
  state.setAttribute("role", "status");
  const spinner = element("span", "spinner");
  spinner.setAttribute("aria-hidden", "true");
  state.append(spinner, textElement("span", message));
  return state;
}

export function stateCard(title, message, { error = false, action = null } = {}) {
  const card = element("div", `state-card${error ? " is-error" : ""}`);
  card.setAttribute("role", error ? "alert" : "status");
  card.append(textElement("span", error ? "!" : "i", "state-mark"));
  const copy = element("div");
  copy.append(textElement("h3", title), textElement("p", message));
  if (action) {
    const actions = element("div", "state-action");
    actions.append(action);
    copy.append(actions);
  }
  card.append(copy);
  return card;
}

export function table(columns, rows, emptyMessage = "No records are available.") {
  const scroll = element("div", "table-scroll");
  const tableNode = element("table", "data-table");
  const head = element("thead");
  const headerRow = element("tr");
  for (const column of columns) headerRow.append(textElement("th", column.label));
  head.append(headerRow);
  tableNode.append(head);

  const body = element("tbody");
  if (!rows.length) {
    const row = element("tr");
    const cell = textElement("td", emptyMessage, "empty-cell");
    cell.colSpan = columns.length;
    row.append(cell);
    body.append(row);
  } else {
    for (const record of rows) {
      const row = element("tr");
      for (const column of columns) {
        const cell = element("td");
        const value = column.render(record);
        if (value instanceof Node) cell.append(value);
        else cell.textContent = value === null || value === undefined ? "—" : String(value);
        row.append(cell);
      }
      body.append(row);
    }
  }
  tableNode.append(body);
  scroll.append(tableNode);
  return scroll;
}

export function pager({ offset, total, limit, onChange }) {
  const nav = element("div", "pager");
  const first = total === 0 ? 0 : offset + 1;
  const last = Math.min(offset + limit, total);
  nav.append(textElement("span", `${first}–${last} of ${total}`, "pager-info"));
  const actions = element("div", "pager-actions");
  const previous = actionButton("Previous", () => onChange(Math.max(0, offset - limit)));
  previous.disabled = offset <= 0;
  const next = actionButton("Next", () => onChange(offset + limit));
  next.disabled = offset + limit >= total;
  actions.append(previous, next);
  nav.append(actions);
  return nav;
}

export function field(labelText, control, className = "field") {
  const wrapper = element("div", className);
  const label = textElement("label", labelText);
  if (control.id) label.htmlFor = control.id;
  wrapper.append(label, control);
  return wrapper;
}

export function selectControl(id, options, value = "") {
  const select = element("select");
  select.id = id;
  for (const option of options) {
    const item = textElement("option", option.label);
    item.value = option.value;
    select.append(item);
  }
  select.value = value;
  return select;
}

export function inputControl(id, type, placeholder, value = "") {
  const input = element("input");
  input.id = id;
  input.type = type;
  input.placeholder = placeholder;
  input.value = value;
  return input;
}

export function panel(title, subtitle = "") {
  const wrapper = element("section", "panel");
  const heading = element("div", "panel-heading");
  const copy = element("div");
  copy.append(textElement("h3", title));
  if (subtitle) copy.append(textElement("p", subtitle));
  heading.append(copy);
  wrapper.append(heading);
  const body = element("div", "panel-body");
  wrapper.append(body);
  return { wrapper, body };
}

export function detailField(label, value) {
  const item = element("div", "detail-item");
  item.append(textElement("dt", label), textElement("dd", value));
  return item;
}
