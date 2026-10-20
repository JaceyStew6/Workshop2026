"""API du moteur de remédiation.

  POST /v1/incidents      (jeton X-Service-Token)  : réservé au détecteur ML
  GET  /v1/incidents[/id] (lecture seule)          : dashboard
  GET  /v1/state          (lecture seule)          : état perçu du service (up/degraded/down) + incidents
  GET  /healthz, /metrics

Lancement : uvicorn main:app_factory --factory   (le câblage vient de l'environnement)
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
import sys
import time
from collections import deque
from typing import Any, Dict, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel, Field, field_validator

from adapters import DockerController, HttpProbe, HttpWaf
from engine import FINAL, Engine, IncidentIn, Settings

INCIDENTS = Counter("remediation_incidents_total", "Incidents terminés", ["state"])
MTTR = Histogram("remediation_duration_seconds", "Durée alerte -> état final", buckets=(5, 10, 15, 20, 30, 45, 60, 90, 120, 300))
ACTIONS = Counter("remediation_actions_total", "Actions exécutées", ["action", "result"])
SERVICE_UP = Gauge("service_up", "1 si la sonde perçoit le service comme up")


def secret(env: str) -> str:
    path = os.environ.get(env)
    return open(path).read().strip() if path and os.path.exists(path) else ""


class IncidentBody(BaseModel):
    incident_id: str = Field(pattern=r"^inc-[A-Za-z0-9-]{3,48}$")
    target_service: str = Field(max_length=64)
    suspected_class: Literal["availability", "compromise", "unknown"] = "unknown"
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    detected_at: str = Field(default="", max_length=40)
    source: str = Field(default="", max_length=64)
    evidence: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence")
    @classmethod
    def small_evidence(cls, v):
        if len(json.dumps(v, default=str)) > 4096:
            raise ValueError("evidence trop volumineux")
        return v


def settings_from_env() -> Settings:
    targets = dict(p.split("=", 1) for p in os.environ.get("ALLOWED_TARGETS", "payment-api=resilience-alpha-payment-api-1").split(",") if "=" in p)
    f = lambda k, d: type(d)(os.environ.get(k, d))
    return Settings(
        allowed_targets=targets,
        never_ban={x.strip() for x in os.environ.get("NEVER_BAN", "").split(",") if x.strip()},
        ban_ttl=f("BAN_TTL_SECONDS", 600), ban_min_rps=f("BAN_MIN_RPS", 30.0),
        health_wait=f("HEALTH_WAIT_SECONDS", 20.0), restart_wait=f("RESTART_WAIT_SECONDS", 45.0),
        verify_timeout=f("VERIFY_TIMEOUT_SECONDS", 45.0), poll=f("POLL_SECONDS", 2.0),
        max_restarts=f("MAX_RESTARTS_PER_WINDOW", 3), restart_window=f("RESTART_WINDOW_SECONDS", 300.0))


def create_app(settings: Settings, waf, controller, probe, service_token: str,
               audit_path: Optional[str] = None, monitor_interval: float = 2.0) -> FastAPI:
    engine = Engine(settings, waf, controller, probe, audit_path=audit_path)
    samples: deque = deque(maxlen=900)
    app = FastAPI(title="remediation-engine", docs_url=None, redoc_url=None)
    app.state.engine = engine

    async def monitor():
        sampler = getattr(probe, "sample", None)
        while sampler:
            try:
                s = await sampler()
                samples.append(s)
                SERVICE_UP.set(1 if s["state"] == "up" else 0)
            except Exception:  # la supervision ne doit jamais interrompre la remédiation
                pass
            await asyncio.sleep(monitor_interval)

    @app.on_event("startup")
    async def _start():
        app.state.monitor = asyncio.create_task(monitor())

    @app.on_event("shutdown")
    async def _stop():
        app.state.monitor.cancel()

    def require_token(x_service_token: str = Header(default="")):
        if not service_token or not hmac.compare_digest(x_service_token, service_token):
            raise HTTPException(401, "unauthorized")

    async def observe(inc):
        done = await engine.wait(inc.id, timeout=600)
        INCIDENTS.labels(done.state).inc()
        if done.finished_at:
            MTTR.observe(done.finished_at - done.received_at)
        for st in done.steps:
            ACTIONS.labels(st["action"], "ok" if st["ok"] else "failed").inc()

    @app.post("/v1/incidents", status_code=202, dependencies=[Depends(require_token)])
    async def post_incident(body: IncidentBody):
        try:
            inc, created = engine.submit(IncidentIn(**body.model_dump()))
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        if created:
            asyncio.create_task(observe(inc))
        return {"incident_id": inc.id, "state": inc.state, "created": created}

    @app.get("/v1/incidents")
    async def list_incidents(limit: int = 20):
        items = sorted(engine.incidents.values(), key=lambda i: i.received_at, reverse=True)[:max(1, min(limit, 100))]
        return [i.to_dict() for i in items]

    @app.get("/v1/incidents/{incident_id}")
    async def get_incident(incident_id: str):
        inc = engine.incidents.get(incident_id)
        if not inc:
            raise HTTPException(404, "incident inconnu")
        return inc.to_dict()

    @app.get("/v1/state")
    async def state(history: int = 300):
        last = sorted(engine.incidents.values(), key=lambda i: i.received_at, reverse=True)[:1]
        return {
            "now": time.time(),
            "current": samples[-1] if samples else None,
            "samples": list(samples)[-max(1, min(history, 900)):],
            "open_incidents": [engine.incidents[i].to_dict() for i in engine.active.values()],
            "last_incident": last[0].to_dict() if last else None,
        }

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/metrics")
    async def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


def app_factory() -> FastAPI:
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    st = settings_from_env()
    waf = HttpWaf(os.environ.get("WAF_ADMIN_URL", "http://waf:8082"), secret("WAF_ADMIN_TOKEN_FILE"))
    ctl = DockerController(os.environ.get("DOCKER_HOST", "tcp://docker-restart:2375"))
    probe = HttpProbe(os.environ.get("PROBE_BASE_URL", "http://waf:8081"),
                      os.environ.get("PROBE_USER", "synthetic-probe"), secret("PROBE_PASSWORD_FILE"),
                      public_url=os.environ.get("PROBE_PUBLIC_URL", ""),
                      soak_seconds=float(os.environ.get("PROBE_SOAK_SECONDS", "8")))
    return create_app(st, waf, ctl, probe, secret("SERVICE_TOKEN_FILE"),
                      audit_path=os.environ.get("AUDIT_LOG"))
