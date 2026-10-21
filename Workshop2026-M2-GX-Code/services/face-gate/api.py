"""API HTTP de face-gate (exposée uniquement par le WAF, sous /gate/)."""
from __future__ import annotations

import hmac
import threading
import time
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, generate_latest
from pydantic import BaseModel, Field

from gate import FaceGate, GateError


class Identify(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")


class PasswordIn(BaseModel):
    session_id: str = Field(min_length=32, max_length=32, pattern=r"^[0-9a-f]+$")
    password: str = Field(min_length=1, max_length=128)


class SessionRef(BaseModel):
    session_id: str = Field(min_length=32, max_length=32, pattern=r"^[0-9a-f]+$")


class EnrollIn(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    label: str = Field(default="", max_length=60)


class LedTest(BaseModel):
    pattern: str = Field(max_length=16)
    seconds: float = Field(default=5.0, ge=1, le=15)


def client_ip(request: Request) -> str:
    # face-gate n'est joignable que depuis le réseau interne : l'en-tête est posé par le WAF.
    return (request.headers.get("x-forwarded-for", "") or (request.client.host if request.client else "")).split(",")[0].strip()


def create_app(gate: FaceGate, jwt_secret: str, device_token: str, reaper_interval_s: Optional[float] = 1.0) -> FastAPI:
    app = FastAPI(title="face-gate", docs_url=None, redoc_url=None, openapi_url=None)
    reg = CollectorRegistry()
    AUTH = Counter("gate_auth_total", "Événements d'authentification biométrique", ["event", "result"], registry=reg)
    for ev, rs in (("face", "recognised"), ("face", "denied"), ("face", "blocked"), ("face", "agent_error"),
                   ("password", "ok"), ("password", "failed"), ("password", "blocked"),
                   ("identify", "blocked"), ("identify", "busy"), ("identify", "ip_limited"),
                   ("session", "timeout"), ("session", "cancelled"), ("enroll", "ok"), ("enroll", "error")):
        AUTH.labels(ev, rs)
    CAMERA = Gauge("gate_camera_on", "1 si la caméra du PC Hôte est allumée", registry=reg)
    DEVICE = Gauge("gate_device_online", "1 si l'ESP8266 a interrogé la passerelle depuis moins de 10 s", registry=reg)
    LED = Gauge("gate_led_active", "1 si le voyant est allumé", registry=reg)
    stop = threading.Event()
    gate.on_event = lambda ev, rs: AUTH.labels(ev, rs).inc()

    def sync_metrics() -> None:
        CAMERA.set(1 if gate.camera_is_on else 0)
        DEVICE.set(1 if gate.device_seen and time.time() - gate.device_seen < 10 else 0)
        LED.set(0 if gate.led.read()["pattern"] == "off" else 1)

    def reaper() -> None:
        while not stop.wait(reaper_interval_s):
            try:
                gate.tick()
                sync_metrics()
            except Exception:
                pass

    @app.on_event("startup")
    def _start():
        if reaper_interval_s:
            threading.Thread(target=reaper, daemon=True).start()

    @app.on_event("shutdown")
    def _stop():
        stop.set()
        gate.shutdown_camera()

    @app.exception_handler(GateError)
    async def gate_error(_: Request, exc: GateError):
        return JSONResponse({"detail": exc.message, "code": exc.code, **exc.extra}, status_code=exc.status)

    # ------------------------------------------------------------------ parcours de connexion
    @app.post("/gate/identify")
    def identify(body: Identify, request: Request):
        return gate.identify(body.username, client_ip(request))

    @app.get("/gate/session/{session_id}")
    def session(session_id: str):
        return gate.status(session_id)

    @app.post("/gate/password")
    def password(body: PasswordIn, request: Request):
        return gate.password(body.session_id, body.password, client_ip(request))

    @app.post("/gate/cancel")
    def cancel(body: SessionRef):
        return gate.cancel(body.session_id)

    # ------------------------------------------------------------------ voyant physique (ESP8266)
    @app.get("/gate/device/led")
    def device_led(request: Request, x_device_token: str = Header(default="")):
        if not device_token or not hmac.compare_digest(x_device_token, device_token):
            raise HTTPException(401, "Jeton d'appareil invalide")
        return gate.device_poll(client_ip(request))

    # ------------------------------------------------------------------ administration (JWT + permission)
    def need(perm: str):
        def dep(authorization: Optional[str] = Header(default=None)) -> str:
            if not authorization or not authorization.lower().startswith("bearer "):
                raise HTTPException(401, "Authentification requise")
            try:
                c = jwt.decode(authorization[7:], jwt_secret, algorithms=["HS256"], issuer="resilience-auth",
                               options={"require": ["exp", "sub", "iss"]})
            except jwt.PyJWTError:
                raise HTTPException(401, "Jeton invalide ou expiré")
            perms = c.get("perms", [])
            if perm not in perms or "backoffice:access" not in perms:
                raise HTTPException(403, "Permission insuffisante")
            info = gate.store.user_info(c["sub"])
            if not info or not info["active"]:
                raise HTTPException(403, "Compte désactivé")
            return c["sub"]
        return dep

    @app.get("/gate/faces")
    def faces(username: Optional[str] = None, actor: str = Depends(need("backoffice:faces"))):
        return gate.store.list_templates(username)

    @app.post("/gate/faces/enroll", status_code=202)
    def enroll(body: EnrollIn, request: Request, actor: str = Depends(need("backoffice:faces"))):
        return gate.start_enroll(body.username, body.label, actor, client_ip(request))

    @app.get("/gate/faces/enroll/{job_id}")
    def enroll_status(job_id: str, actor: str = Depends(need("backoffice:faces"))):
        return gate.enroll_status(job_id)

    @app.delete("/gate/faces/{template_id}")
    def delete_face(template_id: int, request: Request, actor: str = Depends(need("backoffice:faces"))):
        return gate.delete_face(template_id, actor, client_ip(request))

    @app.get("/gate/device")
    def device(actor: str = Depends(need("backoffice:device"))):
        return gate.device_status()

    @app.post("/gate/device/test")
    def device_test(body: LedTest, request: Request, actor: str = Depends(need("backoffice:device"))):
        return gate.led_test(body.pattern, body.seconds, actor, client_ip(request))

    @app.post("/gate/camera/off")
    def camera_off(request: Request, actor: str = Depends(need("backoffice:device"))):
        gate.shutdown_camera()
        gate.store.audit(actor, "camera.force_off", "", {}, client_ip(request))
        return {"camera": "off"}

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/metrics")
    def metrics():
        sync_metrics()
        return Response(generate_latest(reg), media_type=CONTENT_TYPE_LATEST)

    return app
