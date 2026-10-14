# SOC dashboard

This is a dependency-free browser client built with HTML, CSS, and JavaScript
modules. It uses the existing authenticated FastAPI routes and displays only
records returned by that API. Untrusted values are inserted into DOM text nodes
using `textContent`.

From the project root, serve the static files on loopback:

```bash
python3 -m http.server 4173 --bind 127.0.0.1 --directory frontend
```

Open `http://127.0.0.1:4173`. Start the backend with
`SOC_CORS_ORIGINS=http://127.0.0.1:4173` and sign in with an active account.
An administrator must create the initial account using the instructions in
the [API guide](../docs/api.md). Existing configured bearers remain available
through the alternate sign-in mode. Passwords are used only for the login
request; bearer tokens remain in page memory and **Sign out** calls the
revocation endpoint. Full installation, authentication, CORS, role, and
limitation details are in the root [README](../README.md).

## Investigation views

The Incidents view reads incident details and notes from the existing
`GET /api/v1/incidents/{incident_id}` and
`GET /api/v1/incidents/{incident_id}/notes` endpoints. Analysts and admins see
notes oldest first and can append a note with the existing `POST` note route;
the dashboard reloads the note page after the API confirms the append. Note
text is rendered using DOM text nodes. Readers cannot access incident routes,
and the backend enforces note permissions independently of the UI.

Administrators see the Audit history navigation item. Its read-only table uses
`GET /api/v1/admin/audit-events` with pagination and only the API-supported
exact-match filters: `action`, `resource_type`, and `resource_id`. The view
does not render the raw audit `changes` object or API-token resource IDs. It
shows a short fixed summary, actor metadata, action, timestamp, and safe
resource labels. The backend independently requires an administrator role.

Both views show loading, empty, access-restricted, expired-session, and API
error states. An expired bearer clears from memory and returns the page to
sign-in. The dashboard uses no sample records. Audit history is append-only at
the application/database layer; it is not tamper-proof against direct SQLite
or filesystem access, as described in the [API guide](../docs/api.md).
