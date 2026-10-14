# Current local architecture

```text
JSONL / Suricata EVE
        │
        ▼
 parser → normalizer → detection engine
                          │
                          ▼
             SQLite repository adapter
               ├─ normalized events
               ├─ alerts and event references
               └─ incidents and linked records
                          ▲
                          │
                 incident service
```

The parser, normalizer, JSONL reader, detection engine, and Suricata EVE reader
remain independent of persistence. `SQLiteRepository` owns SQL, schema
constraints, transactions, stable event references, and relational links.
`IncidentService` owns incident validation and status transitions and depends
on the `IncidentRepository` protocol rather than SQLite implementation details.
That boundary is the replacement point for a future PostgreSQL adapter.

SQLite is used for local development and relies only on Python's standard
library. Events use the same canonical SHA-256 `event:<digest>` reference as
the detection engine. Generated alert identifiers are preserved. Foreign-key
tables link alerts to their supporting events and incidents to their alerts and
events. Duplicate event or alert writes with identical content are idempotent;
reuse of an identifier for different content is a conflict.

Incidents start as `open`. The allowed transitions are `open → investigating`,
`investigating → open` or `resolved`, and `resolved → investigating` or
`closed`. `closed` is terminal. Reopening a resolved incident clears its
`resolved_at`; resolving and closing set UTC timestamps. Metadata updates do
not bypass the status-transition service.
