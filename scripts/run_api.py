"""Start the local API only on an explicitly loopback bind address."""

from __future__ import annotations

import ipaddress
import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def validate_bind_host(host: str) -> str:
    """Return a literal loopback address, rejecting aliases and all other hosts.

    Mapping ``localhost`` to 127.0.0.1 avoids relying on host-file or DNS
    resolution when Uvicorn creates its listening socket. IPv6 loopback can be
    selected explicitly with ``::1`` on systems with IPv6 support.
    """
    if not isinstance(host, str) or not host or host != host.strip():
        raise ValueError("SOC_API_BIND_HOST must be a loopback hostname or IP address.")
    if host.lower() == "localhost":
        return "127.0.0.1"
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(
            "SOC_API_BIND_HOST must be localhost or a loopback IP address."
        ) from exc
    if not address.is_loopback:
        raise ValueError("The API bind address must be loopback-only.")
    return str(address)


def configured_port(value: str | None) -> int:
    if value is None:
        return 8000
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("SOC_API_PORT must be an integer from 1 through 65535.") from exc
    if not 1 <= port <= 65535 or str(port) != value:
        raise ValueError("SOC_API_PORT must be an integer from 1 through 65535.")
    return port


def main() -> None:
    host = validate_bind_host(os.getenv("SOC_API_BIND_HOST", "127.0.0.1"))
    port = configured_port(os.getenv("SOC_API_PORT"))
    import uvicorn

    uvicorn.run("backend.app.main:app", host=host, port=port)


if __name__ == "__main__":
    try:
        main()
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
