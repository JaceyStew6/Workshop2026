"""Clients HTTP de face-gate : agent caméra (PC Hôte) et auth-service."""
from __future__ import annotations

import httpx

from gate import AgentError, AuthRejected, AuthUnavailable


class HttpAgent:
    def __init__(self, base_url: str, token: str):
        self._c = httpx.Client(base_url=base_url, headers={"Authorization": f"Bearer {token}"}, timeout=5.0)

    def _call(self, method: str, path: str, **kw) -> dict:
        try:
            r = self._c.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise AgentError(f"agent injoignable: {exc.__class__.__name__}") from exc
        if r.status_code >= 400:
            raise AgentError(f"agent HTTP {r.status_code}")
        return r.json()

    def camera_on(self, max_seconds: int) -> None:
        self._call("POST", "/v1/camera/on", json={"max_seconds": max(5, min(max_seconds, 300))})

    def embed(self, frames: int, timeout_s: float) -> dict:
        return self._call("POST", "/v1/camera/embed", json={"frames": frames, "timeout_s": timeout_s},
                          timeout=timeout_s + 5.0)

    def camera_off(self) -> None:
        self._call("POST", "/v1/camera/off")

    def health(self) -> dict:
        return self._call("GET", "/v1/health", timeout=2.0)


class HttpAuth:
    def __init__(self, base_url: str):
        self._c = httpx.Client(base_url=base_url, timeout=2.0)

    def login(self, username: str, password: str, ticket: str, ip: str) -> dict:
        try:
            r = self._c.post("/auth/token", json={"username": username, "password": password, "face_ticket": ticket},
                             headers={"x-forwarded-for": ip})
        except httpx.HTTPError as exc:
            raise AuthUnavailable() from exc
        if r.status_code == 200:
            return r.json()
        if r.status_code in (401, 403, 429):
            raise AuthRejected(r.status_code)
        raise AuthUnavailable()
