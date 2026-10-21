"""WAF applicatif : reverse proxy + règles + ban IP + métriques + journaux SIEM.

Trois écouteurs, un seul processus :
  8080  public   : trafic des clients (et de l'attaquant). Seul port publié sur le réseau du hotspot.
  8081  interne  : mêmes règles, mais jamais banni -> utilisé par la sonde de remédiation pour tester
                   le VRAI chemin applicatif sans être victime de ses propres bans.
  8082  admin    : API de bannissement (jeton obligatoire), /healthz et /metrics. Réseau ops.

Choix de conception important : le WAF NE bloque PAS sur le débit. La décision "cette IP sature le
service" appartient à la chaîne ML -> remédiation (c'est la démonstration). Le WAF applique les
signatures (SQLi, XSS...) et exécute les bans qu'on lui ordonne.
"""
from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import logging
import os
import signal
import sys
import time
import uuid
from typing import Optional

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel, Field

import rules
from bans import BanList, BanRefused


def secret(env: str) -> str:
    path = os.environ.get(env)
    return open(path).read().strip() if path and os.path.exists(path) else ""


AUTH_URL = os.environ.get("AUTH_URL", "http://auth-service:8000")
PAYMENT_URL = os.environ.get("PAYMENT_URL", "http://payment-api:8000")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://frontend:8080")
GATE_URL = os.environ.get("GATE_URL", "http://face-gate:8000")
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "2.5"))
MAX_BODY = int(os.environ.get("MAX_BODY_BYTES", "65536"))
ADMIN_TOKEN = secret("WAF_ADMIN_TOKEN_FILE")
TRUSTED_PROXIES = [ipaddress.ip_network(x.strip()) for x in os.environ.get("TRUSTED_PROXIES", "").split(",") if x.strip()]
NEVER_BAN = [x for x in os.environ.get("NEVER_BAN", "").split(",") if x.strip()]
LABEL_CAP = 500

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
       "transfer-encoding", "upgrade", "host", "content-length"}

REQS = Counter("waf_requests_total", "Requêtes vues par le WAF", ["client_ip", "status"])
BLOCKED = Counter("waf_blocked_total", "Requêtes bloquées", ["reason"])
for _reason in ("banned", "too_large", "signature"):   # séries créées à 0 : sinon increase() ignore la 1re rafale
    BLOCKED.labels(_reason)
LAT = Histogram("waf_request_duration_seconds", "Durée totale côté WAF", buckets=(.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5))
CONNS = Gauge("waf_connections_active", "Requêtes en cours de traitement")
BANS_ACTIVE = Gauge("waf_bans_active", "Bans actifs")
UP_ERR = Counter("waf_upstream_errors_total", "Erreurs vers l'amont", ["kind"])
# Télémétrie du voyant ESP8266 (1 requête/s, jeton d'appareil) : ce n'est pas du trafic client. Les réponses 200 sont
# comptées à part pour ne pas déformer les caractéristiques de trafic apprises par le détecteur ML ; tout échec (401,
# 5xx...) reste compté comme n'importe quelle requête, donc visible.
DEVICE_POLL_PATH = "/gate/device/led"
DEVICE_POLLS = Counter("waf_device_polls_total", "Interrogations réussies du voyant ESP8266")

access = logging.getLogger("waf.access")
access.setLevel(logging.INFO)
_h = logging.StreamHandler(sys.stdout)
_h.setFormatter(logging.Formatter("%(message)s"))
access.addHandler(_h)
access.propagate = False

bans = BanList(path=os.environ.get("BAN_FILE", "/var/lib/waf/bans.json"), never_ban=NEVER_BAN,
               max_ttl=int(os.environ.get("BAN_MAX_TTL", "3600")), max_active=int(os.environ.get("BAN_MAX_ACTIVE", "100")))
_seen_ips: set = set()
client: Optional[httpx.AsyncClient] = None


def label_ip(ip: str) -> str:
    """Borne la cardinalité Prometheus (un attaquant qui falsifie sa source ne doit pas saturer le TSDB)."""
    if ip in _seen_ips:
        return ip
    if len(_seen_ips) >= LABEL_CAP:
        return "other"
    _seen_ips.add(ip)
    return ip


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else "0.0.0.0"
    if TRUSTED_PROXIES:
        try:
            if any(ipaddress.ip_address(peer) in net for net in TRUSTED_PROXIES):
                xff = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                if xff:
                    return str(ipaddress.ip_address(xff))
        except ValueError:
            pass
    return peer


def log_event(**fields):
    fields["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int(time.time() * 1000) % 1000:03d}Z"
    access.info(json.dumps(fields, ensure_ascii=False, separators=(",", ":")))


def route_for(path: str) -> str:
    if path.startswith("/auth/"):
        return AUTH_URL
    if path.startswith("/api/"):
        return PAYMENT_URL
    if path.startswith("/gate/"):
        return GATE_URL
    return FRONTEND_URL


async def read_body(request: Request) -> Optional[bytes]:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY:
        return None
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def make_proxy_app(internal: bool) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    listener = "internal" if internal else "public"

    async def handler(request: Request, full_path: str):
        t0 = time.perf_counter()
        CONNS.inc()
        rid = uuid.uuid4().hex[:12]
        ip = client_ip(request)
        path = request.url.path
        status, action, hits, score = 500, "allow", [], 0
        try:
            if not internal and bans.is_banned(ip):
                status, action = 403, "banned"
                BLOCKED.labels("banned").inc()
                return Response(json.dumps({"error": "forbidden", "request_id": rid}), 403, media_type="application/json")

            body = await read_body(request)
            if body is None:
                status, action = 413, "too_large"
                BLOCKED.labels("too_large").inc()
                return Response(json.dumps({"error": "payload_too_large", "request_id": rid}), 413, media_type="application/json")

            hdrs = {k.lower(): v for k, v in request.headers.items()}
            score, hits = rules.inspect(path, request.url.query, hdrs, body)
            if rules.should_block(score):
                status, action = 403, "blocked"
                BLOCKED.labels("signature").inc()
                return Response(json.dumps({"error": "forbidden", "request_id": rid}), 403, media_type="application/json")

            fwd = {k: v for k, v in request.headers.items() if k.lower() not in HOP}
            fwd["x-forwarded-for"] = ip
            fwd["x-request-id"] = rid
            url = route_for(path) + path + (f"?{request.url.query}" if request.url.query else "")
            try:
                up = await client.request(request.method, url, content=body, headers=fwd)
            except httpx.TimeoutException:
                status, action = 504, "upstream_timeout"
                UP_ERR.labels("timeout").inc()
                return Response(json.dumps({"error": "upstream_timeout", "request_id": rid}), 504, media_type="application/json")
            except httpx.HTTPError:
                status, action = 502, "upstream_error"
                UP_ERR.labels("connect").inc()
                return Response(json.dumps({"error": "bad_gateway", "request_id": rid}), 502, media_type="application/json")

            status = up.status_code
            headers = {k: v for k, v in up.headers.items() if k.lower() not in HOP and k.lower() != "server"}
            headers.update({"x-content-type-options": "nosniff", "x-frame-options": "DENY",
                            "referrer-policy": "no-referrer", "x-request-id": rid})
            return Response(up.content, status, headers=headers)
        finally:
            CONNS.dec()
            dt = time.perf_counter() - t0
            if path == DEVICE_POLL_PATH and status == 200:
                DEVICE_POLLS.inc()
            else:
                LAT.observe(dt)
                REQS.labels(label_ip(ip), str(status)).inc()
            if action != "allow" or status >= 400 or hits:
                # journalisation ciblée : anomalies uniquement, jamais corps ni en-têtes d'authentification
                log_event(event="waf", listener=listener, rid=rid, client_ip=ip, method=request.method,
                          path=path[:200], status=status, action=action, rules=hits, score=score,
                          ua=request.headers.get("user-agent", "")[:120], ms=round(dt * 1000, 1))

    app.add_api_route("/{full_path:path}", handler, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])

    @app.on_event("startup")
    async def _start():
        global client
        client = httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT,
                                   limits=httpx.Limits(max_connections=200, max_keepalive_connections=50))

    @app.on_event("shutdown")
    async def _stop():
        await client.aclose()

    if internal:
        @app.get("/healthz", include_in_schema=False)
        async def healthz_internal():
            return {"status": "ok"}
    return app


class BanIn(BaseModel):
    ip: str = Field(max_length=45)
    ttl_seconds: int = Field(default=600, ge=1, le=86400)
    reason: str = Field(default="", max_length=200)
    incident_id: str = Field(default="", max_length=64)


def make_admin_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def auth(request: Request):
        token = request.headers.get("x-admin-token", "")
        if not ADMIN_TOKEN or not hmac.compare_digest(token, ADMIN_TOKEN):
            log_event(event="admin_denied", client_ip=request.client.host if request.client else "?", path=request.url.path)
            raise HTTPException(401, "unauthorized")

    @app.post("/v1/bans", status_code=201)
    async def add_ban(request: Request, body: BanIn):
        auth(request)
        try:
            entry = bans.ban(body.ip, body.ttl_seconds, body.reason, body.incident_id, by="remediation-engine")
        except BanRefused as exc:
            log_event(event="ban_refused", ip=body.ip, why=str(exc), incident_id=body.incident_id)
            raise HTTPException(422, str(exc))
        BANS_ACTIVE.set(len(bans.active()))
        log_event(event="ban_added", ip=body.ip, ttl=entry["ttl"], reason=body.reason, incident_id=body.incident_id)
        return {"ip": body.ip, "ttl_seconds": entry["ttl"]}

    @app.delete("/v1/bans/{ip}")
    async def remove_ban(request: Request, ip: str):
        auth(request)
        removed = bans.unban(ip)
        BANS_ACTIVE.set(len(bans.active()))
        log_event(event="ban_removed", ip=ip, existed=removed)
        return {"removed": removed}

    @app.get("/v1/bans")
    async def list_bans(request: Request):
        auth(request)
        now = time.time()
        return [{"ip": ip, "remaining_s": int(b["expires"] - now), "reason": b["reason"], "incident_id": b["incident_id"]}
                for ip, b in bans.active().items()]

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/metrics")
    async def metrics():
        BANS_ACTIVE.set(len(bans.active()))
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


async def serve():
    host = os.environ.get("BIND", "0.0.0.0")
    specs = [(make_proxy_app(False), int(os.environ.get("WAF_PUBLIC_PORT", "8080"))),
             (make_proxy_app(True), int(os.environ.get("WAF_INTERNAL_PORT", "8081"))),
             (make_admin_app(), int(os.environ.get("WAF_ADMIN_PORT", "8082")))]
    servers = [uvicorn.Server(uvicorn.Config(a, host=host, port=p, log_level="warning", access_log=False,
                                             backlog=2048, timeout_keep_alive=5,
                                             server_header=False)) for a, p in specs]
    loop = asyncio.get_running_loop()

    def stop():
        for s in servers:
            s.should_exit = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop)
    for s in servers:                       # un seul gestionnaire de signaux : le nôtre
        s.install_signal_handlers = lambda: None
    await asyncio.gather(*(s.serve() for s in servers))


if __name__ == "__main__":
    asyncio.run(serve())
