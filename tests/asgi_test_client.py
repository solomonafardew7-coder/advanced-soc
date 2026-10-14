"""Small synchronous facade over HTTPX's in-process ASGI transport.

The installed Starlette TestClient's AnyIO portal hangs in this local test
environment before startup. This helper still exercises FastAPI routing,
middleware, dependency injection, and lifespan without opening a network port.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx2


class ASGITestClient:
    __test__ = False

    def __init__(self, app: Any, *, base_url: str = "http://127.0.0.1"):
        self.app = app
        self.base_url = base_url

    def __enter__(self) -> "ASGITestClient":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def request(self, method: str, url: str, **kwargs):
        async def make_request():
            async with self.app.router.lifespan_context(self.app):
                transport = httpx2.ASGITransport(app=self.app)
                async with httpx2.AsyncClient(
                    transport=transport, base_url=self.base_url
                ) as client:
                    return await client.request(method, url, **kwargs)

        return asyncio.run(make_request())

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)

    def patch(self, url: str, **kwargs):
        return self.request("PATCH", url, **kwargs)

    def options(self, url: str, **kwargs):
        return self.request("OPTIONS", url, **kwargs)
