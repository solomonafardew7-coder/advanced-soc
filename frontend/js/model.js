/** Presentation-only helpers for real records returned by the API. */

export function formatTimestamp(value) {
  if (typeof value !== "string" || value.length === 0) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(date);
}

export function filterRecords(records, query, searchableFields) {
  const normalized = String(query ?? "").trim().toLocaleLowerCase();
  if (!normalized) return records;
  return records.filter((record) => searchableFields(record)
    .some((value) => String(value ?? "").toLocaleLowerCase().includes(normalized)));
}

export function compactId(value, visible = 20) {
  if (typeof value !== "string" || value.length <= visible) return value || "—";
  return `${value.slice(0, visible)}…`;
}

export function summaryText(value, maxLength = 96) {
  let text;
  try {
    text = typeof value === "string" ? value : JSON.stringify(value ?? {});
  } catch {
    text = "Details unavailable";
  }
  if (!text) return "—";
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}
