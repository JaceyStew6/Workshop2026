"""Adaptateurs de production : WAF (API d'admin), Docker (via docker-socket-proxy), sonde transactionnelle."""
from __future__ import annotations

import asyncio
import time
import uuid
from typing import Tuple

import httpx

from engine import ProbeResult


class HttpWaf:
    def __init__(self, admin_url: str, token: str):
        self.url, self.token = admin_url.rstrip("/"), token

    async def ban(self, ip: str, ttl: int, reason: str, incident_id: str) -> Tuple[bool, str]:
        try:
            async with httpx.AsyncClient(timeout=3.0) as c:
                r = await c.post(f"{self.url}/v1/bans", headers={"X-Admin-Token": self.token},
                                 json={"ip": ip, "ttl_seconds": ttl, "reason": reason, "incident_id": incident_id})
            return (r.status_code == 201, f"WAF HTTP {r.status_code}: {r.text[:120]}")
        except httpx.HTTPError as exc:
            return False, f"WAF injoignable: {type(exc).__name__}"


class DockerController:
    """Parle UNIQUEMENT à un docker-socket-proxy filtré (restart + inspect). Défense en profondeur :
    on vérifie en plus le label `resilience.remediable=true` avant tout redémarrage."""

    def __init__(self, docker_host: str):
        self.base = docker_host.replace("tcp://", "http://").rstrip("/")

    async def _inspect(self, c: httpx.AsyncClient, container: str):
        r = await c.get(f"{self.base}/containers/{container}/json")
        r.raise_for_status()
        return r.json()

    async def restart(self, container: str) -> Tuple[bool, str]:
        try:
            async with httpx.AsyncClient(timeout=30.0) as c:
                info = await self._inspect(c, container)
                if info.get("Config", {}).get("Labels", {}).get("resilience.remediable") != "true":
                    return False, "refus : le conteneur n'a pas le label resilience.remediable=true"
                r = await c.post(f"{self.base}/containers/{container}/restart", params={"t": 5})
            return (r.status_code == 204, f"Docker HTTP {r.status_code}")
        except httpx.HTTPError as exc:
            return False, f"Docker injoignable: {type(exc).__name__}"

    async def healthy(self, container: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as c:
                state = (await self._inspect(c, container)).get("State", {})
            return bool(state.get("Running")) and state.get("Health", {}).get("Status", "healthy") == "healthy"
        except httpx.HTTPError:
            return False


class HttpProbe:
    """Sonde SYNTHÉTIQUE : emprunte le même chemin qu'un vrai client (WAF -> auth -> API -> base).

    Verdict "service rétabli" = les 5 étapes passent :
      1 devis public   2 connexion   3 paiement PROBE-A <-> PROBE-B   4 relecture du paiement   5 grand livre cohérent
    Le compte de la sonde ne peut manipuler QUE ses deux comptes dédiés (contrôlé côté API).
    """

    def __init__(self, base_url: str, username: str, password: str, timeout: float = 3.0, public_url: str = "",
                 soak_seconds: float = 8.0):
        self.base, self.user, self.pwd, self.timeout = base_url.rstrip("/"), username, password, timeout
        # chemin PUBLIC (celui des vrais clients, soumis aux bans et à la saturation) : sert à l'état perçu et à la
        # vérification de stabilité. Le listener interne n'est jamais banni et peut répondre alors que les clients, non.
        self.pub = (public_url or base_url).rstrip("/")
        self.soak = soak_seconds
        self._flip = False

    async def sample(self) -> dict:
        """Mesure continue pour le dashboard : état perçu par un client (up / degraded / down)."""
        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=3.0) as c:
                r = await c.get(f"{self.pub}/api/fees/quote", params={"amount": 1})
            ms = round((time.perf_counter() - t0) * 1000)
            status = r.status_code
        except httpx.HTTPError:
            ms, status = round((time.perf_counter() - t0) * 1000), 0
        state = "up" if status == 200 and ms < 500 else ("degraded" if status == 200 else "down")
        return {"ts": time.time(), "state": state, "status": status, "ms": ms}

    async def quick(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=1.5) as c:
                r = await c.get(f"{self.pub}/api/fees/quote", params={"amount": 1})
            return r.status_code == 200 and r.elapsed.total_seconds() < 1.0
        except httpx.HTTPError:
            return False

    async def full(self) -> ProbeResult:
        steps = []

        def rec(name: str, ok: bool, t0: float, detail: str = ""):
            steps.append({"step": name, "ok": ok, "ms": round((time.perf_counter() - t0) * 1000), "detail": detail})
            return ok

        async with httpx.AsyncClient(timeout=self.timeout, base_url=self.base) as c:
            try:
                t0 = time.perf_counter()
                r = await c.get("/api/fees/quote", params={"amount": 1})
                if not rec("quote", r.status_code == 200, t0, f"HTTP {r.status_code}"):
                    return ProbeResult(False, steps)

                t0 = time.perf_counter()
                r = await c.post("/auth/token", json={"username": self.user, "password": self.pwd})
                if not rec("login", r.status_code == 200, t0, f"HTTP {r.status_code}"):
                    return ProbeResult(False, steps)
                auth = {"Authorization": f"Bearer {r.json()['access_token']}"}

                src, dst = ("PROBE-B", "PROBE-A") if self._flip else ("PROBE-A", "PROBE-B")
                self._flip = not self._flip
                t0 = time.perf_counter()
                r = await c.post("/api/payments", headers=auth,
                                 json={"from": src, "to": dst, "amount": "1.00", "idempotency_key": f"probe-{uuid.uuid4()}"})
                if not rec("payment", r.status_code == 201 and r.json().get("status") == "COMPLETED", t0, f"HTTP {r.status_code}"):
                    return ProbeResult(False, steps)
                tx_id = r.json()["id"]

                t0 = time.perf_counter()
                r = await c.get(f"/api/payments/{tx_id}", headers=auth)
                if not rec("readback", r.status_code == 200 and r.json().get("status") == "COMPLETED", t0, f"HTTP {r.status_code}"):
                    return ProbeResult(False, steps)

                t0 = time.perf_counter()
                r = await c.get("/api/ledger/integrity", headers=auth)
                ok = r.status_code == 200 and r.json().get("consistent") is True
                rec("ledger", ok, t0, r.text[:120] if not ok else "somme des soldes = total attendu")
                if not ok:
                    return ProbeResult(False, steps)
                # stabilité côté clients : le chemin PUBLIC doit rester rapide pendant toute la durée d'observation (1 Hz).
                # Un redémarrage pendant une saturation qui continue donne souvent quelques secondes de répit : sans cette
                # observation, on déclarerait « rétabli » un service qui retombe aussitôt.
                t0 = time.perf_counter()
                n, good = max(1, int(self.soak)), 0
                for _ in range(n):
                    if not await self.quick():
                        break
                    good += 1
                    await asyncio.sleep(1.0)
                ok = good == n
                rec("public_path", ok, t0, f"{good}/{n} devis publics rapides sur {n} s")
                return ProbeResult(ok, steps)
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                steps.append({"step": "exception", "ok": False, "ms": 0, "detail": type(exc).__name__})
                return ProbeResult(False, steps)
