"""payment-api : transactions SIMULÉES (aucune donnée bancaire réelle).

Points d'architecture utiles à la résilience :
  * /healthz interroge réellement la base (un conteneur "up" mais sans DB est "unhealthy")
  * /api/ledger/integrity expose l'invariant comptable : la somme des soldes est constante.
    La sonde de remédiation s'en sert pour prouver que les DONNÉES sont cohérentes après reprise.
  * /api/fees/quote est PUBLIC et coûteux (simulation de scoring de risque) : c'est la surface
    d'attaque applicative réaliste du scénario de saturation (déni de service applicatif).
  * pool de connexions volontairement petit : une saturation produit des 503 visibles et mesurables.
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
import uuid
from decimal import Decimal
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from psycopg.errors import UniqueViolation
from psycopg_pool import ConnectionPool, PoolTimeout
from pydantic import BaseModel, ConfigDict, Field, condecimal


def secret(env: str) -> str:
    path = os.environ.get(env)
    return open(path).read().strip() if path and os.path.exists(path) else ""


DB = dict(host=os.environ.get("DB_HOST", "localhost"), port=int(os.environ.get("DB_PORT", "5432")),
          dbname=os.environ.get("DB_NAME", "payments"), user=os.environ.get("DB_USER", "payment_svc"),
          password=secret("DB_PASSWORD_FILE"))
JWT_SECRET = secret("JWT_SECRET_FILE")
RISK_ITER = int(os.environ.get("RISK_COST_ITER", "30000"))      # coût CPU du scoring (paramétrable)
PROBE_ACCOUNTS = {"PROBE-A", "PROBE-B"}

logging.basicConfig(level=logging.INFO, format='{"ts":"%(asctime)s","svc":"payment","lvl":"%(levelname)s","msg":"%(message)s"}')
log = logging.getLogger("payment")

pool = ConnectionPool(
    conninfo=" ".join(f"{k}={v}" for k, v in DB.items() if v != ""),
    min_size=1, max_size=int(os.environ.get("DB_POOL_MAX", "5")), timeout=float(os.environ.get("DB_POOL_TIMEOUT", "2.0")),
    open=False)

LATENCY = Histogram("http_request_duration_seconds", "Latence HTTP", ["method", "route", "status"],
                    buckets=(.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10))
TX = Counter("payments_total", "Paiements traités", ["status"])

app = FastAPI(title="payment-api", docs_url=None, redoc_url=None)


@app.on_event("startup")
def startup() -> None:
    pool.open(wait=True, timeout=30)


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


def risk_score(seed: str, iterations: int = RISK_ITER) -> int:
    """Scoring de risque factice mais RÉELLEMENT coûteux en CPU (PBKDF2)."""
    digest = hashlib.pbkdf2_hmac("sha256", seed.encode(), b"risk-engine", iterations)
    return digest[0] % 100


class Principal(BaseModel):
    sub: str
    role: str
    perms: list[str] = []


def current_user(authorization: Optional[str] = Header(default=None)) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Authentification requise")
    try:
        claims = jwt.decode(authorization[7:], JWT_SECRET, algorithms=["HS256"], issuer="resilience-auth",
                            options={"require": ["exp", "sub", "iss"]})
    except jwt.PyJWTError:
        raise HTTPException(401, "Jeton invalide ou expiré")
    return Principal(sub=claims["sub"], role=claims.get("role", "user"), perms=claims.get("perms", []))


def require(perm: str):
    """Habilitation portée par le JWT (émise par auth-service d'après le rôle). Pas de permission = 403."""
    def dep(user: Principal = Depends(current_user)) -> Principal:
        if perm not in user.perms:
            raise HTTPException(403, "Habilitation insuffisante")
        return user
    return dep


class PaymentIn(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    src: str = Field(alias="from", pattern=r"^[A-Z0-9-]{3,32}$")
    dst: str = Field(alias="to", pattern=r"^[A-Z0-9-]{3,32}$")
    amount: condecimal(gt=Decimal("0"), le=Decimal("10000"), decimal_places=2)  # type: ignore[valid-type]
    idempotency_key: Optional[str] = Field(default=None, max_length=64)


def db_unavailable(exc: Exception):
    log.error("base indisponible: %s", exc)
    return HTTPException(503, "Service temporairement indisponible")


@app.get("/api/fees/quote")
def fee_quote(amount: float = Query(gt=0, le=10000)):
    """Endpoint PUBLIC : simulation des frais. Coûteux par conception (scoring + lecture base)."""
    try:
        with pool.connection() as conn:
            conn.execute("SELECT 1")
            score = risk_score(f"quote:{amount}")
    except PoolTimeout as exc:
        raise db_unavailable(exc)
    fee = round(0.4 + amount * 0.002 + score * 0.001, 2)
    return {"amount": amount, "fee": fee, "currency": "EUR"}


@app.post("/api/payments", status_code=201)
def create_payment(p: PaymentIn, user: Principal = Depends(require("payments:create"))):
    if p.src == p.dst:
        raise HTTPException(422, "Comptes source et destination identiques")
    if user.role == "probe" and not ({p.src, p.dst} <= PROBE_ACCOUNTS):
        raise HTTPException(403, "La sonde est limitée à ses comptes dédiés")

    risk_score(f"pay:{p.src}:{p.dst}:{p.amount}", RISK_ITER // 6)
    tx_id = uuid.uuid4()
    rejected = False
    try:
        with pool.connection() as conn:
            with conn.transaction():
                rows = conn.execute(
                    "SELECT id, owner, balance FROM accounts WHERE id = ANY(%s) ORDER BY id FOR UPDATE",
                    ([p.src, p.dst],)).fetchall()
                accounts = {r[0]: r for r in rows}
                if len(accounts) != 2:
                    raise HTTPException(404, "Compte inconnu")
                if accounts[p.src][1] != user.sub:
                    TX.labels("forbidden").inc()
                    raise HTTPException(403, "Le compte source ne vous appartient pas")
                if accounts[p.src][2] < p.amount:
                    # la trace du rejet doit être COMMITÉE : on ne lève l'exception qu'après la transaction
                    conn.execute(
                        "INSERT INTO transactions (id,src,dst,amount,status,created_by) VALUES (%s,%s,%s,%s,'REJECTED',%s)",
                        (tx_id, p.src, p.dst, p.amount, user.sub))
                    rejected = True
                else:
                    conn.execute("UPDATE accounts SET balance = balance - %s WHERE id=%s", (p.amount, p.src))
                    conn.execute("UPDATE accounts SET balance = balance + %s WHERE id=%s", (p.amount, p.dst))
                    conn.execute(
                        "INSERT INTO transactions (id,src,dst,amount,status,idempotency_key,created_by) "
                        "VALUES (%s,%s,%s,%s,'COMPLETED',%s,%s)",
                        (tx_id, p.src, p.dst, p.amount, p.idempotency_key, user.sub))
    except UniqueViolation:
        raise HTTPException(409, "Clé d'idempotence déjà utilisée")
    except PoolTimeout as exc:
        raise db_unavailable(exc)
    if rejected:
        TX.labels("rejected").inc()
        raise HTTPException(409, "Solde insuffisant")
    TX.labels("completed").inc()
    return {"id": str(tx_id), "status": "COMPLETED", "amount": str(p.amount)}


@app.get("/api/payments/{tx_id}")
def get_payment(tx_id: uuid.UUID, user: Principal = Depends(require("payments:read"))):
    try:
        with pool.connection() as conn:
            row = conn.execute(
                "SELECT id, src, dst, amount, status, created_by, created_at FROM transactions WHERE id=%s",
                (tx_id,)).fetchone()
    except PoolTimeout as exc:
        raise db_unavailable(exc)
    if not row or (row[5] != user.sub and user.role != "probe"):
        raise HTTPException(404, "Transaction introuvable")
    return {"id": str(row[0]), "from": row[1], "to": row[2], "amount": str(row[3]),
            "status": row[4], "created_at": row[6].isoformat()}


@app.get("/api/payments")
def list_payments(limit: int = Query(10, ge=1, le=100), user: Principal = Depends(require("payments:read"))):
    try:
        with pool.connection() as conn:
            rows = conn.execute(
                "SELECT id, src, dst, amount, status, created_at FROM transactions WHERE created_by=%s "
                "ORDER BY created_at DESC LIMIT %s", (user.sub, limit)).fetchall()
    except PoolTimeout as exc:
        raise db_unavailable(exc)
    return [{"id": str(r[0]), "from": r[1], "to": r[2], "amount": str(r[3]), "status": r[4],
             "created_at": r[5].isoformat()} for r in rows]


@app.get("/api/ledger/integrity")
def integrity(user: Principal = Depends(current_user)):
    """Invariant comptable : somme des soldes == total initial. Réservé à la sonde."""
    if user.role != "probe":
        raise HTTPException(403, "Réservé à la sonde de supervision")
    try:
        with pool.connection() as conn:
            total = conn.execute("SELECT COALESCE(SUM(balance),0) FROM accounts").fetchone()[0]
            expected = conn.execute("SELECT value FROM ledger_meta WHERE key='expected_total'").fetchone()[0]
            completed = conn.execute("SELECT count(*) FROM transactions WHERE status='COMPLETED'").fetchone()[0]
    except PoolTimeout as exc:
        raise db_unavailable(exc)
    return {"total": str(total), "expected": str(expected), "consistent": total == expected,
            "completed_transactions": completed}


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
