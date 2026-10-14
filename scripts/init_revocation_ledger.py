"""Explicitly initialize trusted revocation state from the SQLite database."""

from __future__ import annotations

import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.database import SQLiteRepository, StorageError
from backend.app.security import HmacRevocationLedger, RevocationStateError


def main() -> int:
    database_path = Path(
        os.getenv("SOC_DATABASE_PATH", str(PROJECT_ROOT / "data" / "soc_platform.sqlite3"))
    ).expanduser()
    try:
        ledger = HmacRevocationLedger.from_environment()
        if database_path.resolve() == ledger.path.resolve():
            raise RevocationStateError(
                "The revocation journal must be stored separately from SQLite."
            )
        repository = SQLiteRepository(database_path)
        repository.initialize()
        known_revocations = repository.list_api_token_revocations()
        ledger.initialize(known_revocations)
    except (OSError, RevocationStateError, StorageError, ValueError) as exc:
        print(f"Could not initialize trusted revocation state: {exc}", file=sys.stderr)
        return 1

    print(
        "Initialized trusted revocation state "
        f"({len(known_revocations)} existing SQLite revocation(s) imported)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
