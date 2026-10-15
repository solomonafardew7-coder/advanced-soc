[![Advanced SOC CI](https://github.com/solomonafardew7-coder/advanced-soc/actions/workflows/tests.yml/badge.svg)](https://github.com/solomonafardew7-coder/advanced-soc/actions/workflows/tests.yml)

# Advanced SOC Cybersecurity Platform

A modular local platform for security-event ingestion, normalization,
detection, Suricata EVE JSON reading, SQLite persistence, incident management,
and a browser dashboard. The current dashboard reads real records from the
local FastAPI API; it does not load sample security records or generate alerts.

## Requirements

- Parrot OS with Python 3.10 or newer.
- A browser with ES module support.
- No Node.js, npm, external font, CDN, cloud service, or paid dependency is
  required for the dashboard.

## Install and test

Run from the project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

The frontend structural checks are included in the pytest suite. They check
that the browser client uses existing API routes, does not persist bearer
tokens, uses text nodes for untrusted values, and includes responsive and
accessible UI structure.

## Configure authentication and start the backend

In a terminal from the project root, activate `.venv`, then create a random
client token. The token itself is not stored in source or passed to backend
configuration; the backend receives its SHA-256 digest, role, and issue time.

```bash
source .venv/bin/activate
SOC_API_CLIENT_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
SOC_API_CLIENT_HASH="$(SOC_API_CLIENT_TOKEN="$SOC_API_CLIENT_TOKEN" python -c 'import hashlib, os; print(hashlib.sha256(os.environ["SOC_API_CLIENT_TOKEN"].encode()).hexdigest())')"
export SOC_API_TOKEN_HASHES="$(SOC_API_CLIENT_HASH="$SOC_API_CLIENT_HASH" python -c 'import datetime, json, os; print(json.dumps({os.environ["SOC_API_CLIENT_HASH"]: {"role": "admin", "issued_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")}}))')"
export SOC_API_TOKEN_TTL_SECONDS=43200
export SOC_DATABASE_PATH="$PWD/data/soc_platform.sqlite3"
export SOC_CORS_ORIGINS="http://127.0.0.1:4173"
printf 'Keep this one-time bootstrap admin token private: %s\n' "$SOC_API_CLIENT_TOKEN"
```

Keep the printed token private. Use it to create the first account with the
interactive instructions in [docs/api.md](docs/api.md). Each allowlist entry includes a `role` and an
ISO-8601 UTC `issued_at` timestamp and may include an explicit timezone-aware
`expires_at`. Set `SOC_API_TOKEN_TTL_SECONDS` to a value from 1 to 7,776,000
seconds; the default is 43,200 seconds (12 hours). Expiration is calculated
from `issued_at` and does not reset when the API restarts. Changing the
configured TTL changes expiration for configured grants without `expires_at`,
so keep it stable unless intentionally changing their lifetimes. Use the admin
API below to add regular tokens; no built-in account or default token exists.
Existing role-only allowlist entries must be converted to grant objects.

Before the first API start, initialize the trusted revocation journal once. The
initializer imports any revocations already in SQLite and refuses to replace
an existing journal. Generate and protect the key in a separate file; do not
regenerate it during routine restarts or recovery.

```bash
install -d -m 700 "$HOME/.config/advanced-soc" "$HOME/.local/state/advanced-soc"
umask 077
( set -o noclobber; python -c 'import secrets; print(secrets.token_hex(32))' > "$HOME/.config/advanced-soc/revocation.key" )
chmod 600 "$HOME/.config/advanced-soc/revocation.key"
export SOC_API_REVOCATION_LEDGER_KEY="$(< "$HOME/.config/advanced-soc/revocation.key")"
export SOC_API_REVOCATION_LEDGER_PATH="$HOME/.local/state/advanced-soc/token-revocations.jsonl"
python scripts/init_revocation_ledger.py
```

Run the initializer only for a new installation. For later terminal sessions,
re-export the API settings above, load the existing key and journal path, and
start the API:

```bash
export SOC_API_REVOCATION_LEDGER_KEY="$(< "$HOME/.config/advanced-soc/revocation.key")"
export SOC_API_REVOCATION_LEDGER_PATH="$HOME/.local/state/advanced-soc/token-revocations.jsonl"
python scripts/run_api.py
```

Missing, altered, or unverifiable trusted state prevents the API from starting.

The supported API startup method is `python scripts/run_api.py`. It defaults
to `127.0.0.1`; `localhost` is normalized to the literal `127.0.0.1`, and
loopback IPs such as `127.0.0.1` or `::1` are accepted. IPv6 requires local OS
support. `SOC_API_PORT` may be 1 through 65535. Wildcard addresses (`0.0.0.0`,
`::`) and all non-loopback addresses are rejected before Uvicorn is called.
CORS is restricted to the exact dashboard origin in the command above; do not
add a wildcard origin.

Do not start the API with a direct Uvicorn command such as
`uvicorn backend.app.main:app --host 0.0.0.0`. Uvicorn can create its listener
before the application middleware runs. That middleware rejects requests on a
reported non-loopback address, but it does not prevent the listener from being
opened. Direct Uvicorn invocation is unsupported for local startup. This
repository has no alternate Uvicorn config, Docker startup command, or project
development-server command.

The configured administrator grant is the initial bootstrap credential. Use it
to create the first account and issue regular tokens through the authenticated
admin API. Account creation does not automatically promote an existing grant
or create default credentials.

### Issue and rotate API tokens

Only an authenticated `admin` bearer can issue tokens. The endpoint returns a
new high-entropy secret once; SQLite stores its SHA-256 digest, role, and
expiration, never the raw bearer token. For example, issue a one-day analyst
token with the bootstrap admin token:

```bash
curl -sS -X POST http://127.0.0.1:8000/api/v1/admin/tokens \
  -H "Authorization: Bearer $SOC_API_CLIENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"role":"analyst","expires_in_seconds":86400}'
```

Save `access_token` in a private credential store immediately; the API will
not display it again. Keep the returned `token_hash` for later revocation. The
default lifetime is `SOC_API_TOKEN_TTL_SECONDS` (12 hours by default);
`expires_in_seconds` may be 1 through 7,776,000 (90 days). To rotate, issue a
replacement, securely deliver it, verify it works, then revoke the old token by
its returned hash. For administrator rotation, verify the replacement admin
token first and use it to revoke the previous admin token. The API rejects
revoking the credential used on the current request. The returned expiry is
stored and does not change if the global default later changes.

Revoke a token using the digest returned at issuance:

```bash
export SOC_TARGET_TOKEN_HASH='paste-the-token_hash-value-here'
curl -sS -X POST http://127.0.0.1:8000/api/v1/admin/tokens/revoke \
  -H "Authorization: Bearer $SOC_API_CLIENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"token_hash\":\"$SOC_TARGET_TOKEN_HASH\"}"
unset SOC_TARGET_TOKEN_HASH
```

### Create accounts, sign in, and disable access

Only an `admin` bearer can create accounts. Usernames are case-insensitive and
must contain 3–64 ASCII letters, digits, dots, underscores, or hyphens.
Passwords must contain 12–256 characters. Passwords are hashed with Argon2id
using `pwdlib`'s recommended parameters; plaintext passwords and password
hashes are never returned by the API. There is no default account. Use the
configured bootstrap admin token to create the first account. The following
prompts for the new password without putting it in shell history:

```bash
SOC_API_CLIENT_TOKEN="$SOC_API_CLIENT_TOKEN" python - <<'PY'
import getpass
import json
import os
import urllib.request

payload = {
    "username": input("New username: "),
    "password": getpass.getpass("New password: "),
    "role": "analyst",
}
request = urllib.request.Request(
    "http://127.0.0.1:8000/api/v1/admin/users",
    data=json.dumps(payload).encode(),
    headers={
        "Authorization": f"Bearer {os.environ['SOC_API_CLIENT_TOKEN']}",
        "Content-Type": "application/json",
    },
    method="POST",
)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(request) as response:
    print(response.read().decode())
PY
```

Sign in at `POST /api/v1/auth/login` with a username and password. It returns
a bearer token with the configured `SOC_API_TOKEN_TTL_SECONDS` lifetime (12
hours by default), its digest, and expiration. The response is marked
`no-store`; handle the returned token like a password. The dashboard now has
an account password sign-in screen; [docs/api.md](docs/api.md) includes
interactive API sign-in and logout commands that prompt for secrets. The
dashboard's **Sign out** action calls `POST /api/v1/auth/logout`. An administrator can disable an
account using `POST /api/v1/admin/users/{user_id}/disable`; this revokes all
account-linked tokens and credentials issued by that account, and writes an
account-disable marker to the trusted revocation journal. Disabled accounts
cannot be re-enabled through the API; create a new account if access is needed
again.

On API startup, SQLite adds the `api_users` table and nullable `user_id` and
`issued_by_user_id` columns to `api_tokens` when needed. Existing token
rows remain unlinked and retain their existing roles, expiration, and
revocation behavior; no existing token is invalidated and no manual migration
or data reset is required. The additive `audit_events` and `incident_notes`
tables are also created on startup; they do not backfill previous actions or
convert incident descriptions into notes. Keep the same `SOC_DATABASE_PATH`
across restarts.
Follow the [API guide](docs/api.md) to back up SQLite together with the
separate revocation journal and key, and to restore SQLite while preserving
current trusted state.

## Start the dashboard

In a second terminal from the project root:

```bash
python3 -m http.server 4173 --bind 127.0.0.1 --directory frontend
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173), enter
`http://127.0.0.1:8000`, and sign in with an active account. Create the initial
account first with the configured bootstrap admin token using the instructions
in [docs/api.md](docs/api.md). The optional configured-bearer sign-in remains
available for existing static or administrator-issued tokens. Bearers stay in
page memory only; **Sign out** calls the API revocation endpoint and reload or
an API 401 clears the local credential. The dashboard accepts only loopback
API addresses.

## Dashboard views and API access

- **Overview:** total alerts, critical alerts, open incidents, and recent
  normalized events. Data is requested from the existing API; metrics outside
  the signed-in role show an access-restricted state.
- **Alerts:** severity, source IP, any destination IP present in alert evidence,
  timestamp, detection description, rule, details, severity/rule filters, and
  search over the currently loaded page. Alert details can create a linked
  incident with the alert and supporting event references.
- **Incidents:** status, severity, creation time, linked record counts, filters,
  details, and supported status-transition actions. Analysts can investigate
  and resolve; administrators can also reopen and close when the lifecycle
  allows it. Analyst and admin detail views include chronologically ordered,
  paginated investigation notes and an append form backed by the existing note
  API.
- **Audit history:** an admin-only, read-only, paginated view backed by
  `GET /api/v1/admin/audit-events`. Filters use the API's exact `action`,
  `resource_type`, and `resource_id` parameters. The UI does not render raw
  change payloads or API-token resource identifiers.
- **Events:** normalized event type, source, timestamp, IP, severity, details,
  filters, and a detail view.
- **System health:** the existing API health route and local integration
  capabilities included in this build.

The dashboard uses the existing `POST /api/v1/auth/login` and
`POST /api/v1/auth/logout` routes, plus `GET /api/v1/health`, `/alerts`,
`/events`, `/incidents`, their detail routes, incident note list/append routes,
and the admin audit list route. The backend grants permissions for `reader`,
`analyst`, and `admin`; `reader` can read alerts, while event, incident, and
note routes require `analyst` or `admin`, and audit history requires `admin`.
API 401 responses clear the in-memory bearer and return to sign-in; 403
responses show an access-restricted state. UI role restrictions are for
usability; the backend remains the authorization boundary.

## Data and limitations

The dashboard does not use mock alerts, incidents, or events. Empty API
responses are shown as empty states; ingest local or authorized records through
the existing ingestion and detection pipeline before expecting populated
views. Search scans only the records loaded in the current page; the backend
does not expose full-text search.

Alerts are immutable detection results and do not contain a workflow status;
the dashboard marks alert status as **Not tracked**. Investigation state is
tracked on linked incidents. The backend now stores append-only incident notes
and audit events in SQLite. Analysts and admins can read notes in chronological
order and append notes from incident details. Incident descriptions remain
editable metadata, separate from the note history. Assignment is not
implemented.

The admin-only audit API records successful login/logout, account and token
administration, incident creation/updates/transitions, note append actions, and
authorization denials. Audit entries include actor type, role, account
snapshot when available, action, resource, UTC timestamp, and a bounded change
summary. Passwords, bearer values, token hashes, note text, and full incident
descriptions are excluded. Account-backed tokens are attributed to their
account; configured or delegated tokens have no asserted username and are
identified by token type and role. SQLite triggers and the absence of ordinary
API update/delete routes reject row edits and deletes. This is append-only at
the application/database layer, not tamper-proof against someone with direct
database or filesystem access, who could replace the database or remove its
triggers. Audit rows are committed in the same SQLite transaction as their
associated account, token, incident, and note mutations. The existing
application audit logger remains enabled as an additional local log.
The dashboard's admin audit view displays actor, role, action, resource type,
and timestamp with short fixed summaries. It omits raw audit `changes`, token
resource identifiers, note text, and incident descriptions. Note content is
shown only in its incident note history to authorized analyst/admin roles.

The existing API has no integration-status route: the health page can identify
the included Suricata EVE JSONL reader, but cannot report whether Suricata is
running or connected. Threat-intelligence providers are not part of this
milestone.

This is local development software and has not had an independent security
review. Do not expose the development server or API to untrusted networks.

## Implemented integrations and security limits

- **Implemented:** local JSONL ingestion and normalization, configurable local
  detection rules, passive parsing of local Suricata EVE JSONL files, SQLite
  event/alert/incident storage, and the versioned FastAPI endpoints documented
  in [the API guide](docs/api.md).
- **Not implemented:** a running Suricata process or live packet capture,
  threat-intelligence providers/enrichment, PostgreSQL, refresh tokens,
  password reset or account recovery, account reactivation or role editing,
  multi-factor authentication, login rate limiting, and alert
  workflow status. User accounts support admin-created roles, Argon2id password
  login, logout, and permanent disablement. Browser sign-in uses the existing
  opaque bearer API and keeps the token in JavaScript memory. Secure HttpOnly
  cookies are not implemented: they would need a backend cookie/session design,
  CSRF protections, and credentialed CORS/same-origin changes. A memory-only
  bearer can still be read by malicious same-origin JavaScript, so this is not
  a substitute for browser-origin security or a production security review.
  The health response reports API availability only; it does not
  monitor the database or integrations. The dashboard's Suricata label means
  the local reader module is available, not that a sensor is running.
- **Local security boundaries:** the supported API launcher and static server
  bind only to loopback. Middleware rejects requests if a directly started
  ASGI server reports a non-loopback bind address, but that check occurs after
  the server may open a listener. Direct Uvicorn startup is unsupported; use
  only `python scripts/run_api.py`. CORS is disabled unless
  explicitly configured, rejects `*`, accepts only valid `localhost`,
  `127.0.0.1`, or `::1` HTTP(S) origins, and does not enable credentialed
  requests. The browser client accepts only loopback API URLs and keeps bearer
  tokens in page memory. Static allowlisted tokens retain their configured TTL
  behavior; grants may set their own `expires_at`. Database-issued tokens have
  individual expiration times. Expiration and revocation are checked on
  protected requests. Admins issue tokens through the authenticated API and
  revoke another token by its digest; self-revocation is rejected. Issued-token
  records and a copy of revocations persist in SQLite. A separate
  HMAC-authenticated journal, configured with
  `SOC_API_REVOCATION_LEDGER_PATH` and `SOC_API_REVOCATION_LEDGER_KEY`, is
  checked on startup and for each protected request. Revocation is written to
  that journal before SQLite, so a failed SQLite write does not make the token
  usable. For backup, stop the API and save SQLite, the journal, and key as one
  protected recovery set. During a SQLite-only restore, preserve the current
  journal and key; this prevents later revocations from being undone by the
  supported restore procedure. SQLite and a local HMAC journal cannot detect
  coordinated rollback of the journal and key. Remote or hardware-backed
  monotonic checkpoints would be needed for that threat; neither is
  implemented. Do not expose the service to an untrusted network.
- **Data handling:** SQLite queries bind supplied values as parameters. API
  validation and database failures return generic errors; audit logs record
  actions and roles without bearer tokens or request bodies. Dashboard values
  from the API are inserted as text nodes. These checks do not replace an
  independent security review.

The full pytest suite includes a temporary-database integration test that
passes synthetic events through the detection engine, SQLite repository, API,
and incident lifecycle. Run it together with the frontend contract checks:

```bash
source .venv/bin/activate
python -m pytest -q
```

## Troubleshooting

- **Could not reach the local API:** start the backend and keep it bound to
  `127.0.0.1:8000`.
- **Browser reports a CORS/network error:** start the backend with
  `SOC_CORS_ORIGINS=http://127.0.0.1:4173`, before Uvicorn imports the app.
- **401 Unauthorized:** verify the account is active and the token has not
  expired or been revoked, then sign in again. A 401 clears the token held in
  the current dashboard tab.
- **403 Access restricted:** use a role allowed for that view. Readers can see
  alerts; event and incident data require analyst or administrator access.
- **Empty views:** the dashboard does not load sample JSONL records. Run the
  local ingestion and detection pipeline and persist records first.
- **503 unavailable:** check that the API token allowlist is configured, the
  local SQLite database can be opened, and the server is bound to loopback.

See [docs/installation.md](docs/installation.md) for ingestion, detection,
Suricata EVE, storage, and incident-management commands, and
[docs/api.md](docs/api.md) for API authentication details.
