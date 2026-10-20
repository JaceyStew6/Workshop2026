"""auth-service : émission de JWT pour le SI de paiement fictif.

Sécurité :
  * mots de passe hachés avec scrypt (sel aléatoire par utilisateur)
  * même temps de réponse pour utilisateur inconnu / mauvais mot de passe (hachage factice)
  * verrouillage temporaire après 5 échecs / 5 min par utilisateur (anti brute force)
  * secrets lus depuis des fichiers (*_FILE), jamais depuis l'environnement en clair
  * rôle SQL limité à la table users
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from collections import defaultdict, deque

import jwt
import psycopg
from fastapi import FastAPI, HTTPException, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field


def secret(env: str, default: str = "") -> str:
    path = os.environ.get(env)
    return open(path).read().strip() if path and os.path.exists(path) else default


DB = dict(host=os.environ.get("DB_HOST", "localhost"), port=int(os.environ.get("DB_PORT", "5432")),
          dbname=os.environ.get("DB_NAME", "payments"), user=os.environ.get("DB_USER", "auth_svc"),
          password=secret("DB_PASSWORD_FILE"))
JWT_SECRET = secret("JWT_SECRET_FILE")
TOKEN_TTL = int(os.environ.get("TOKEN_TTL_SECONDS", "900"))
SCRYPT_N = int(os.environ.get("SCRYPT_N", str(2 ** 14)))
LOCK_AFTER, LOCK_WINDOW = 5, 300

logging.basicConfig(level=logging.INFO, format='{"ts":"%(asctime)s","svc":"auth","lvl":"%(levelname)s","msg":"%(message)s"}')
log = logging.getLogger("auth")

pool = ConnectionPool(
    conninfo=" ".join(f"{k}={v}" for k, v in DB.items() if v != ""),
    min_size=1, max_size=int(os.environ.get("DB_POOL_MAX", "5")), timeout=2.0, open=False)

LOGINS = Counter("auth_login_total", "Tentatives de connexion", ["result"])
for _r in ("success", "failure", "locked"):   # séries créées à 0 : sinon rate()/increase() ignorent la 1re rafale
    LOGINS.labels(_r)
LATENCY = Histogram("http_request_duration_seconds", "Latence HTTP", ["method", "route", "status"],
                    buckets=(.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10))

app = FastAPI(title="auth-service", docs_url=None, redoc_url=None)
_failures: dict[str, deque] = defaultdict(deque)
_lock = threading.Lock()


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=8, p=1, dklen=32)
    return f"scrypt${SCRYPT_N}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    _, n, salt, expected = stored.split("$")
    dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=8, p=1, dklen=32)
    return hmac.compare_digest(dk.hex(), expected)


DUMMY_HASH = hash_password("not-a-real-password")


@app.on_event("startup")
def startup() -> None:
    pool.open(wait=True, timeout=30)
    seed = [("demo-user", secret("DEMO_PASSWORD_FILE"), "user"),
            ("synthetic-probe", secret("PROBE_PASSWORD_FILE"), "probe")]
    with pool.connection() as conn:
        for username, password, role in seed:
            if not password:
                continue
            exists = conn.execute("SELECT 1 FROM users WHERE username=%s", (username,)).fetchone()
            if not exists:
                conn.execute("INSERT INTO users (username, password_hash, role) VALUES (%s,%s,%s)",
                             (username, hash_password(password), role))
                log.info("utilisateur de démonstration créé: %s", username)


@app.middleware("http")
async def metrics_mw(request, call_next):
    t0 = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        route = request.scope.get("route")
        LATENCY.labels(request.method, getattr(route, "path", "unmatched"), str(status)).observe(time.perf_counter() - t0)


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=128)


def locked(username: str) -> bool:
    now = time.time()
    with _lock:
        q = _failures[username]
        while q and now - q[0] > LOCK_WINDOW:
            q.popleft()
        return len(q) >= LOCK_AFTER


@app.post("/auth/token")
def token(creds: Credentials):
    if locked(creds.username):
        LOGINS.labels("locked").inc()
        raise HTTPException(429, "Trop de tentatives, réessayez plus tard")
    try:
        with pool.connection() as conn:
            row = conn.execute("SELECT password_hash, role FROM users WHERE username=%s",
                               (creds.username,)).fetchone()
    except Exception as exc:
        log.error("base indisponible: %s", exc)
        raise HTTPException(503, "Service temporairement indisponible")

    stored = row[0] if row else DUMMY_HASH
    ok = verify_password(creds.password, stored) and row is not None
    if not ok:
        with _lock:
            _failures[creds.username].append(time.time())
        LOGINS.labels("failure").inc()
        log.warning("echec authentification user=%s", creds.username)
        raise HTTPException(401, "Identifiants invalides")

    now = int(time.time())
    LOGINS.labels("success").inc()
    return {"access_token": jwt.encode({"sub": creds.username, "role": row[1], "iat": now, "exp": now + TOKEN_TTL,
                                        "iss": "resilience-auth"}, JWT_SECRET, algorithm="HS256"),
            "token_type": "bearer", "expires_in": TOKEN_TTL}


@app.get("/healthz")
def healthz():
    try:
        with pool.connection(timeout=1.0) as conn:
            conn.execute("SELECT 1")
        return {"status": "ok"}
    except Exception:
        raise HTTPException(503, "database unavailable")


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
