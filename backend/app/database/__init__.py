"""Database adapters for local and future replaceable storage backends."""

from backend.app.database.sqlite_repository import (
    SQLiteRepository,
    StorageConflictError,
    StorageError,
    StorageValidationError,
    event_reference,
)

__all__ = [
    "SQLiteRepository",
    "StorageConflictError",
    "StorageError",
    "StorageValidationError",
    "event_reference",
]
