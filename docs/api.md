# Local FastAPI backend

Milestone 6 adds a versioned local HTTP API at `/api/v1`. It reuses the SQLite
repository and incident service. The API does not start event ingestion or
detection automatically; events and alerts must already be stored using those
components.

## Install and start on Parrot OS

Run from the project root. Python 3.10 or newer is required.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

Generate a high-entropy client bearer token. The application configuration
contains only its SHA-256 digest, role, and UTC issue time; keep the printed
token private.

```bash
SOC_API_CLIENT_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
SOC_API_CLIENT_HASH="$(SOC_API_CLIENT_TOKEN="$SOC_API_CLIENT_TOKEN" python -c 'import hashlib, os; print(hashlib.sha256(os.environ["SOC_API_CLIENT_TOKEN"].encode()).hexdigest())')"
export SOC_API_TOKEN_HASHES="$(SOC_API_CLIENT_HASH="$SOC_API_CLIENT_HASH" python -c 'import datetime, json, os; print(json.dumps({os.environ["SOC_API_CLIENT_HASH"]: {"role": "admin", "issued_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")}}))')"
export SOC_API_TOKEN_TTL_SECONDS=43200
export SOC_DATABASE_PATH="$PWD/data/soc_platform.sqlite3"
export SOC_CORS_ORIGINS=http://127.0.0.1:4173
printf 'Save this API token securely: %s\n' "$SOC_API_CLIENT_TOKEN"
```

`SOC_API_TOKEN_HASHES` is a JSON object whose keys are lowercase SHA-256 token
digests. Each value contains `role` (`reader`, `analyst`, or `admin`) and a
timezone-aware ISO-8601 `issued_at`; it may also contain a timezone-aware
`expires_at`. Old role-only entries are rejected. Grants without `expires_at`
expire `SOC_API_TOKEN_TTL_SECONDS` after issue time; the default is 43,200
seconds (12 hours), with a maximum of 7,776,000 seconds (90 days). Explicit
per-grant expirations are bounded to 90 days after issue time and are not
changed by the global TTL setting. Expiration does not reset on restart. Keep
the global TTL stable unless intentionally changing lifetimes for grants that
use it.

A configured admin grant is required to bootstrap token issuance. Later
database-issued tokens can authenticate without a configured static grant,
provided the same database is retained. If neither a static grant nor a
database-issued token exists, protected endpoints fail closed. There is no
default account or password. Do not commit a real token or a populated
token-hash configuration to source control.

Start the service using the loopback-only launcher:

```bash
python scripts/run_api.py
```

The launcher binds to `127.0.0.1:8000` by default. `SOC_API_BIND_HOST` accepts
`localhost` (normalized to literal `127.0.0.1`) or a loopback IP such as
`127.0.0.1` or `::1`; IPv6 requires local OS support. `SOC_API_PORT` accepts
ports 1 through 65535. Wildcard and non-loopback addresses fail before the
launcher calls Uvicorn. The ASGI application also returns 503 if its reported
bound address is not loopback.

Use only `python scripts/run_api.py` for local API startup. Direct Uvicorn
invocations, including `uvicorn backend.app.main:app --host 0.0.0.0`, are
unsupported: Uvicorn may open the listening socket before the application
middleware can reject requests. The middleware is a request guard, not a bind
restriction. The repository has no alternate Uvicorn config or Docker startup
command. The default database path is
`data/soc_platform.sqlite3`; override it with `SOC_DATABASE_PATH`. CORS is
disabled by default; the setup example above allows the local dashboard's exact
origin before startup.

The dashboard's static server runs on loopback port 4173. Wildcard origins are
rejected, only loopback HTTP(S) origins are accepted, and credentialed CORS is
disabled.

## Authentication and roles

Send the generated token in the standard HTTP bearer header:

```bash
curl -H "Authorization: Bearer $SOC_API_CLIENT_TOKEN" \
  http://127.0.0.1:8000/api/v1/alerts
```

| Role | Access |
| --- | --- |
| `reader` | Read and filter alerts. |
| `analyst` | Reader access, read events and incidents, create/update incidents, append/read incident notes, and use the `investigating` or `resolved` transition targets when the service lifecycle allows them. |
| `admin` | Analyst access and incident reopen/close operations when the lifecycle allows them; read audit history; create or disable accounts and issue/revoke tokens. |

All event and incident routes require authentication. The health endpoint is
public and returns only service status. Missing or invalid tokens receive 401;
valid credentials without the required role receive 403. The API logs
authentication and incident actions with role/action metadata, but not bearer
tokens, request bodies, or event contents. Successful security and incident
mutations and authorization denials are also persisted in SQLite as described
below.

### User accounts, password login, and logout

An administrator creates persistent accounts through `POST /api/v1/admin/users`.
Usernames are unique without case sensitivity and normalized to lowercase.
They must contain 3–64 ASCII letters, digits, dots, underscores, or hyphens;
whitespace and other characters are rejected.
Passwords must contain 12–256 characters. The API hashes passwords with
Argon2id using `pwdlib`'s recommended settings; the dependency is installed by
`requirements.txt`. Only username, role, active status, and creation time are
returned. Invalid username/password and disabled-account logins return the
same 401 detail. There is no automatic bootstrap account: the configured
administrator bearer is required to create the first account.

Create a user from an interactive local Python prompt so the password is not
placed in shell history. This example uses the configured bootstrap admin
token held in `SOC_API_CLIENT_TOKEN`:

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

Sign in through `POST /api/v1/auth/login` with JSON fields `username` and
`password`. A successful response contains the bearer once, the token digest,
role, issue time, and expiration. It uses the configured default token TTL and
sets `Cache-Control: no-store` and `Pragma: no-cache`. This command prompts for
the password and prints the one-time token response; keep that terminal output
private:

```bash
python - <<'PY'
import getpass
import json
import urllib.request

payload = {
    "username": input("Username: "),
    "password": getpass.getpass("Password: "),
}
request = urllib.request.Request(
    "http://127.0.0.1:8000/api/v1/auth/login",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(request) as response:
    print(response.read().decode())
PY
```

The dashboard sign-in screen calls `POST /api/v1/auth/login` directly and
keeps the returned bearer in JavaScript memory for the current tab. It does not
store the password or bearer in browser storage, a cookie, a URL, or frontend
logs. The optional configured-bearer mode supports existing static and
administrator-issued credentials. A protected API 401 clears the in-memory
bearer and returns the dashboard to sign-in. The login request uses
`Cache-Control: no-store` on the backend, and the browser fetch uses
`cache: "no-store"` and omits cookies.

The dashboard's **Sign out** action calls `POST /api/v1/auth/logout` with the
current bearer. This writes its digest to the trusted revocation journal and
SQLite; later requests with that token receive 401. If the API cannot be
reached during sign-out, the dashboard clears the bearer locally and reports
that server revocation could not be confirmed. In that case the token remains
valid until expiry or until an administrator revokes it.

This dashboard uses the backend's existing bearer authorization model. Secure
HttpOnly cookie authentication is not implemented. Adding it would require
backend cookie/session issuance and deletion, CSRF defenses (including origin
or CSRF-token checks), and a deliberate same-origin or credentialed-CORS
design. CORS currently disallows credentials. The memory-only bearer avoids
long-term browser persistence but cannot protect against malicious JavaScript
running in the trusted dashboard origin.
For interactive logout without entering a token in shell history:

```bash
python - <<'PY'
import getpass
import urllib.request

token = getpass.getpass("Bearer token to log out: ")
request = urllib.request.Request(
    "http://127.0.0.1:8000/api/v1/auth/logout",
    headers={"Authorization": f"Bearer {token}"},
    method="POST",
)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(request) as response:
    print(response.read().decode())
PY
```

An administrator can permanently disable a user with
`POST /api/v1/admin/users/{user_id}/disable`. This marks the account inactive,
revokes its account-linked login tokens, and records a deterministic
account-disable marker in the trusted journal. Tokens issued by an account
administrator are attributed to that issuer and revoked when the issuer is
disabled; the issuer's current active status and admin role are checked on
each request using those credentials. Current account status and role are
checked for every account-linked bearer request. Disabled accounts cannot log
in or use existing tokens, even after a supported SQLite-only restore that
preserves the current journal.
There is no re-enable, role-change, user-list,
password-reset, or account-recovery route. An administrator cannot disable
their own account, and the last active account administrator cannot be
disabled. An analyst has no account-creation, account-disable, token-issue, or
token-revoke permission.

### Issuance, rotation, expiration, and revocation

An authenticated `admin` token can issue a `reader`, `analyst`, or `admin`
token without editing source or restarting the service. The issue endpoint
returns the high-entropy bearer once, sets `Cache-Control: no-store`, and
persists its SHA-256 digest, role, timestamps, and an optional issuing account
identifier in SQLite. Never put the returned bearer in shell history, logs,
tickets, or source control. For example,
issue an analyst token expiring in one day:

```bash
curl -sS -X POST http://127.0.0.1:8000/api/v1/admin/tokens \
  -H "Authorization: Bearer $SOC_API_CLIENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"role":"analyst","expires_in_seconds":86400}'
```

`expires_in_seconds` is optional; when omitted, the service uses the configured
global TTL. A supplied lifetime must be an integer from 1 second through 90
days. The resulting expiration is stored in the database and is not
recalculated if the global TTL later changes. Save `access_token` securely and
retain `token_hash` for revocation. To
rotate a token, issue a replacement, securely deliver and verify it, then
revoke the former token. To rotate an admin credential, call revoke using the
replacement admin credential. The API refuses to revoke the credential used by
the current request.

Revoke a token using its returned digest:

```bash
# SOC_TARGET_TOKEN_HASH is the token_hash returned by the issue endpoint.
export SOC_TARGET_TOKEN_HASH='paste-the-token_hash-value-here'
curl -X POST http://127.0.0.1:8000/api/v1/admin/tokens/revoke \
  -H "Authorization: Bearer $SOC_API_CLIENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"token_hash\":\"$SOC_TARGET_TOKEN_HASH\"}"
unset SOC_TARGET_TOKEN_HASH
```

Only an `admin` token may issue or revoke tokens. There is no unauthenticated
issuance endpoint. The revoke endpoint accepts a digest, not the target raw
token. It appends the revocation to a separate trusted journal before writing
SQLite. If the SQLite write fails, the journal still blocks the token.
Repeated revocations are idempotent. Expiration and revocation are checked for
each recognized token on every protected request. Audit logs include action
and role, not token values or digests.

The API creates its `api_users` and token metadata tables on startup with
`CREATE TABLE IF NOT EXISTS`; existing event, alert, incident, and revocation
tables are preserved. It adds the nullable `revoked_at` and `user_id` columns
and the nullable `issued_by_user_id` column to an older `api_tokens` table if
needed, plus indexes. This is an additive automatic
migration: existing token rows receive null account references and keep their
roles, expiration, and revocation behavior. They are not converted to
accounts, promoted, or invalidated. These legacy grants will not be revoked
automatically when a new account is disabled; revoke them through the existing
administrator token-revocation endpoint if their owner is unknown or access
must end. Login tokens link to the authenticating account. Database-issued
grants record an account administrator as issuer;
tokens issued by the configured static administrator remain unlinked because
static grants have no account identity. Revoke those standalone grants
separately if rotating or disabling a static credential. No manual migration
or data reset is needed; keep the same
`SOC_DATABASE_PATH` across restarts and back it up with the trusted state
described below.

Startup also additively creates `audit_events` and `incident_notes` plus their
indexes and append-only triggers. This does not rewrite or invalidate existing
accounts, tokens, revocations, events, alerts, or incidents. There is no data
backfill: audit history starts with actions taken after this migration, and
existing incident descriptions are not converted into investigation notes.

The database includes security events and incidents as well as token digests,
roles, expiration timestamps, and a copy of revocations. SQLite cannot tell
that an internally consistent database file is an older backup. A separate
HMAC-authenticated journal supplies the trusted revocation state for the
supported SQLite-only recovery procedure.

### Trusted revocation state initialization

Set these values before starting the API:

```bash
export SOC_API_REVOCATION_LEDGER_PATH="$HOME/.local/state/advanced-soc/token-revocations.jsonl"
export SOC_API_REVOCATION_LEDGER_KEY="$(< "$HOME/.config/advanced-soc/revocation.key")"
```

For a new installation, create the private directories and key once, then
initialize the journal. Do not repeat key generation or initialization during
normal restarts:

```bash
install -d -m 700 "$HOME/.config/advanced-soc" "$HOME/.local/state/advanced-soc"
umask 077
( set -o noclobber; python -c 'import secrets; print(secrets.token_hex(32))' > "$HOME/.config/advanced-soc/revocation.key" )
chmod 600 "$HOME/.config/advanced-soc/revocation.key"
export SOC_API_REVOCATION_LEDGER_KEY="$(< "$HOME/.config/advanced-soc/revocation.key")"
export SOC_API_REVOCATION_LEDGER_PATH="$HOME/.local/state/advanced-soc/token-revocations.jsonl"
python scripts/init_revocation_ledger.py
```

The initializer creates the journal only when it does not already exist and
imports revocations currently present in SQLite. It refuses to overwrite an
existing journal. Revocations already lost before this initialization cannot
be reconstructed; rotate credentials if their status is uncertain. At
startup, the API verifies the journal before serving and adds any revocations
found in SQLite. If the journal is missing, corrupt, has unsafe permissions,
or does not match the configured key, startup fails closed. Do not recreate it
from a database backup whose age or revocation completeness is uncertain.

### Backup and restore

Restrict filesystem access to the database, its SQLite WAL/journal sidecars,
the revocation journal, and key. For a consistent recovery set, stop the API,
use SQLite's online backup API rather than copying an active database file, and
copy the journal and key as separately protected files:

```bash
install -d -m 700 "$HOME/soc-backups"
SOC_BACKUP_STEM="$HOME/soc-backups/soc-platform-$(date -u +%Y%m%dT%H%M%SZ)"
SOC_DB_SOURCE="${SOC_DATABASE_PATH:-$PWD/data/soc_platform.sqlite3}" \
SOC_DB_BACKUP="${SOC_BACKUP_STEM}.sqlite3" \
python - <<'PY'
import os
import sqlite3

with sqlite3.connect(os.environ["SOC_DB_SOURCE"]) as source:
    with sqlite3.connect(os.environ["SOC_DB_BACKUP"]) as backup:
        source.backup(backup)
PY
SOC_API_REVOCATION_LEDGER_PATH="${SOC_API_REVOCATION_LEDGER_PATH:-$HOME/.local/state/advanced-soc/token-revocations.jsonl}"
SOC_API_REVOCATION_KEY_FILE="$HOME/.config/advanced-soc/revocation.key"
cp -- "$SOC_API_REVOCATION_LEDGER_PATH" "${SOC_BACKUP_STEM}.revocations.jsonl"
cp -- "$SOC_API_REVOCATION_KEY_FILE" "${SOC_BACKUP_STEM}.revocation.key"
chmod 600 "${SOC_BACKUP_STEM}.sqlite3" "${SOC_BACKUP_STEM}.revocations.jsonl" "${SOC_BACKUP_STEM}.revocation.key"
```

Treat these files as sensitive security records. To restore an older SQLite
database, stop the API and restore only that database while preserving the
current journal and key. At startup, revocations found in SQLite are imported
to the journal; journaled revocations remain effective even when absent from
the restored database. This supported SQLite-only restore does not silently
reactivate a token revoked after the backup. It may lose later events,
incidents, and token-issuance records. Replacing the database without restoring
it loses database-issued grants.

To restore a selected backup into the configured database while the API is
stopped, set its path and run the SQLite backup API in the reverse direction:

```bash
SOC_DB_BACKUP="$HOME/soc-backups/soc-platform-REPLACE_WITH_BACKUP.sqlite3" \
SOC_DB_RESTORE="${SOC_DATABASE_PATH:-$PWD/data/soc_platform.sqlite3}" \
python - <<'PY'
import os
import sqlite3

with sqlite3.connect(os.environ["SOC_DB_BACKUP"]) as backup:
    with sqlite3.connect(os.environ["SOC_DB_RESTORE"]) as destination:
        backup.backup(destination)
PY
```

Confirm the backup path before running recovery; it replaces the target
database contents. Preserve a separate copy of the pre-restore database if it
may be needed for investigation. Do not restore an older journal with an old
SQLite file. Restore a journal/key pair only from a protected recovery set
known to include every later revocation. If the current journal cannot be
verified and no sufficiently recent trusted copy exists, leave the API stopped;
do not rerun initialization against a potentially stale database. Rotate
static configured credentials and treat database-issued credentials as
potentially exposed before any manual recovery.

The local HMAC journal is a separate trusted file, not a remote or hardware
monotonic checkpoint. It detects journal edits that cannot be authenticated,
but by itself cannot detect restoration of an older valid journal (or a
coordinated rollback of the journal and key. The key is passed through the
process environment, so protect the local account and avoid sharing the API
process with untrusted same-user processes. A remote append-only checkpoint
service offers stronger separation but adds network availability and service
operations. A TPM-backed monotonic counter avoids a remote dependency but
requires compatible hardware and platform-specific provisioning. Neither is
implemented. This local design specifically protects the supported procedure
of restoring SQLite while preserving the current journal and key; it is not a
claim of protection against coordinated rollback of all trusted state.
The journal is replayed and authenticated on every protected request, so
verification time and memory use grow with the number of revocations; this is
intended for low-volume local use.

## Version 1 endpoints

All paths below start with `/api/v1`.

| Method and path | Access | Purpose |
| --- | --- | --- |
| `GET /health` | Public | Local service status. |
| `POST /auth/login` | Public | Verify username/password and issue an account-linked bearer token. |
| `POST /auth/logout` | Any valid role | Revoke the bearer token used for this request. |
| `POST /admin/users` | Admin | Create an account with role `reader`, `analyst`, or `admin`. |
| `POST /admin/users/{user_id}/disable` | Admin | Permanently disable an account and revoke its linked and issued tokens. |
| `GET /alerts` | Any configured role | Page alerts; filter by `severity` and `rule_id`. |
| `GET /alerts/{alert_id}` | Any configured role | Read one alert. |
| `GET /events` | Analyst/admin | Page events; filter by `event_type`, `source_ip`, and `severity`. |
| `GET /events/{event_id}` | Analyst/admin | Read one stored event. |
| `GET /incidents` | Analyst/admin | Page incidents; filter by `status` and `severity`. |
| `GET /incidents/{incident_id}` | Analyst/admin | Read an incident. |
| `POST /incidents` | Analyst/admin | Create an open incident. |
| `PATCH /incidents/{incident_id}` | Analyst/admin | Update title, description, or severity. |
| `POST /incidents/{incident_id}/transitions` | Analyst/admin | Apply a validated incident status transition. |
| `GET /incidents/{incident_id}/notes` | Analyst/admin | Page append-only investigation notes for an incident. |
| `POST /incidents/{incident_id}/notes` | Analyst/admin | Append an investigation note (1–5000 characters). |
| `GET /admin/audit-events` | Admin | Page audit history; filter by `action`, `resource_type`, and `resource_id`. |
| `POST /admin/tokens` | Admin | Issue a bearer token; raw value is returned once. |
| `POST /admin/tokens/revoke` | Admin | Revoke a credential by its SHA-256 token hash. |

## Alert investigation workflow

Alerts are immutable detection results. The current alert schema has no alert
status, assignee, or investigation-note fields. The dashboard shows alert
status as untracked and offers **Create linked incident** in alert details.
That action uses the existing `POST /incidents` route with the actual alert ID,
supporting event references, severity, rule name, and detection description.
The created incident appears in the open incident register. No alert or event
records are fabricated or modified.

Incident status is the investigation state. The dashboard exposes only
transitions already supported by the incident service:

| Current status | Analyst | Admin |
| --- | --- | --- |
| `open` | `investigating` | `investigating` |
| `investigating` | `resolved` | `open`, `resolved` |
| `resolved` | `investigating` | `investigating`, `closed` |
| `closed` | — | — |

The UI uses `POST /incidents/{incident_id}/transitions`; the API independently
enforces the authenticated role and lifecycle, so UI visibility is not the
authorization boundary. The dashboard displays incident notes oldest first,
offers an append form to analysts and administrators, and reloads the note page
after a successful append. Assignment is not implemented. Alert-level triage
status remains separate; incident actions do not change detector alert records.

Notes are appended with the authenticated role and, for account-linked tokens,
the author's user ID and username snapshot. Configured and delegated tokens
are recorded with their actor type and role, with no guessed account identity.
Notes are visible only through analyst/admin incident routes and there are no
edit or delete API routes. `GET /admin/audit-events` is admin-only. It returns
event IDs, UTC timestamps, actor metadata, action, resource type/ID, and a
limited JSON change summary. Summaries do not include password or bearer
values, token hashes, note text, or full incident descriptions. Successful
security and incident mutations write the business record and audit row in
one SQLite transaction; role-denial records are appended separately because
they have no corresponding state mutation.

SQLite triggers reject ordinary `UPDATE` and `DELETE` statements against audit
and note rows, and ordinary API routes expose no mutation or deletion methods
for them. This is application/database-level append-only behavior, not
tamper-proofing against someone with direct database or filesystem control.
Such an operator can replace the database or drop its triggers. Keep protected
backups and filesystem permissions; no external immutable audit sink is
implemented. Audit history begins after the additive migration and does not
backfill earlier actions. The dashboard includes a read-only administrator
audit view with pagination and the API's exact-match `action`, `resource_type`,
and `resource_id` filters. It displays actor, role, action, timestamp, resource
type, and a fixed summary; it does not display the raw `changes` object, API
token resource identifiers, note text, or incident descriptions. Note text is
displayed only in its incident history to analyst/admin users. A 401 clears the
in-memory bearer and returns to sign-in; a 403 shows an access-restricted state.
The API independently enforces these role checks. Database or server errors
are shown as generic API errors without echoing submitted note content.

Append a note to an existing incident:

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/incidents/INCIDENT_ID/notes" \
  -H "Authorization: Bearer $SOC_API_CLIENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"note_text":"Reviewed the local synthetic event references."}'
```

Read incident notes as an analyst or admin, and audit history as an admin:

```bash
curl -H "Authorization: Bearer $SOC_API_CLIENT_TOKEN" \
  "http://127.0.0.1:8000/api/v1/incidents/INCIDENT_ID/notes?limit=50&offset=0"
curl -H "Authorization: Bearer $SOC_API_ADMIN_TOKEN" \
  "http://127.0.0.1:8000/api/v1/admin/audit-events?limit=50&offset=0"
```

List endpoints accept `limit` from 1 through 100 and non-negative `offset`;
responses contain `items`, `total`, `limit`, and `offset`. Request models reject
unknown fields and invalid values. API errors are deliberately generic and do
not echo rejected event or incident payloads. Database failures return 503.

Create an incident:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/incidents \
  -H "Authorization: Bearer $SOC_API_CLIENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"title":"Synthetic investigation","description":"Local test case","severity":"medium"}'
```

Move it to investigating (replace the identifier with the response value):

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/incidents/INCIDENT_ID/transitions" \
  -H "Authorization: Bearer $SOC_API_CLIENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"status":"investigating"}'
```

For the interactive local schema, open `http://127.0.0.1:8000/docs` while the
server is running. Keep it loopback-only while using the development server.

## Tests and limitations

The API tests generate disposable in-memory credentials and use a temporary
SQLite file. Run the full suite with:

```bash
python -m pytest -q
```

This is a local development API, not a production security claim. It has not
had an independent security review. Persistent accounts support admin-created
roles, Argon2id password login, logout, and permanent disablement. The local
dashboard supports password sign-in and sign-out through the existing bearer
endpoints. Password reset, account recovery/reactivation, role editing,
multi-factor authentication, login rate limiting, refresh tokens, and HttpOnly
cookie sessions are not implemented. A token remains valid until its individual
expiration or revocation. Issued grants and a copy of revocation records are
stored in SQLite; the separate HMAC journal is checked on every protected
request. A SQLite-only restore that preserves current journal/key state does
not undo later revocations. Restoring an old journal can undo them because the
local journal is not a monotonic checkpoint. The safe launcher
restricts bind hosts to loopback. A direct non-loopback Uvicorn launch can still
open a TCP listener, although middleware rejects every HTTP request; avoid
that launch mode. Do not expose the API to untrusted networks. A remote
deployment needs HTTPS, operational secret management, deployment hardening,
and a security review.
