"""auth-service : émission de JWT et gestion des habilitations du SI de paiement fictif.

Sécurité :
  * mots de passe hachés avec scrypt (sel aléatoire par utilisateur)
  * même temps de réponse pour utilisateur inconnu / mauvais mot de passe (hachage factice)
  * verrouillage temporaire après 5 échecs / 5 min par utilisateur (anti brute force)
  * secrets lus depuis des fichiers (*_FILE), jamais depuis l'environnement en clair
  * rôle SQL limité aux tables users / roles / audit_log
  * utilisateurs du portail (ni compte machine, ni rôle d'administration) : le JWT n'est délivré qu'avec un TICKET FACIAL signé par face-gate (HS256, usage unique,
    120 s). Le navigateur ne détient jamais ce ticket : face-gate l'ajoute lui-même au moment du mot de passe.
  * habilitations : le JWT porte la liste des permissions (`perms`) du rôle ; l'API d'administration vérifie
    aussi en base que l'appelant est toujours actif et que les droits accordés ne dépassent pas les siens.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from typing import Optional

import jwt
import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
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
FACE_TICKET_SECRET = secret("FACE_TICKET_SECRET_FILE")
TOKEN_TTL = int(os.environ.get("TOKEN_TTL_SECONDS", "900"))
SCRYPT_N = int(os.environ.get("SCRYPT_N", str(2 ** 14)))
LOCK_AFTER, LOCK_WINDOW = 5, 300
MIN_PASSWORD_LEN = 12
# Qui doit passer par la caméra ? Les UTILISATEURS du portail de paiement : la reconnaissance faciale est obligatoire, sans option pour
# la désactiver (un utilisateur sans visage inscrit ne peut pas se connecter). Exceptions assumées : les comptes MACHINE (sonde, scripts de
# test) et les comptes d'ADMINISTRATION (rôle portant la permission backoffice:access), qui se connectent par mot de passe seul.
MACHINE_ROLES = {"probe", "automation"}


def needs_face(role: str, perms) -> bool:
    return role not in MACHINE_ROLES and "backoffice:access" not in perms

PERMISSIONS = {
    "payments:create": "Émettre des virements",
    "payments:read": "Consulter ses virements",
    "backoffice:access": "Accéder au back-office",
    "backoffice:users": "Gérer les utilisateurs",
    "backoffice:roles": "Gérer les rôles et habilitations",
    "backoffice:faces": "Gérer les visages enregistrés",
    "backoffice:device": "Superviser le voyant (ESP8266) et la caméra",
    "backoffice:audit": "Consulter le journal d'audit",
}

logging.basicConfig(level=logging.INFO, format='{"ts":"%(asctime)s","svc":"auth","lvl":"%(levelname)s","msg":"%(message)s"}')
log = logging.getLogger("auth")

pool = ConnectionPool(
    conninfo=" ".join(f"{k}={v}" for k, v in DB.items() if v != ""),
    min_size=1, max_size=int(os.environ.get("DB_POOL_MAX", "5")), timeout=2.0, open=False)

LOGINS = Counter("auth_login_total", "Tentatives de connexion", ["result"])
for _r in ("success", "failure", "locked", "face_required"):   # séries créées à 0 : sinon rate()/increase() ignorent la 1re rafale
    LOGINS.labels(_r)
ADMIN_ACTIONS = Counter("auth_admin_actions_total", "Actions d'administration", ["action"])
LATENCY = Histogram("http_request_duration_seconds", "Latence HTTP", ["method", "route", "status"],
                    buckets=(.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10))

app = FastAPI(title="auth-service", docs_url=None, redoc_url=None)
_failures: dict[str, deque] = defaultdict(deque)
_lock = threading.Lock()
_used_tickets: dict[str, float] = {}          # jti -> expiration (usage unique ; 1 seul réplica)


# ------------------------------------------------------------------ mots de passe
def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=8, p=1, dklen=32)
    return f"scrypt${SCRYPT_N}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    _, n, salt, expected = stored.split("$")
    dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=8, p=1, dklen=32)
    return hmac.compare_digest(dk.hex(), expected)


DUMMY_HASH = hash_password("not-a-real-password")


# ------------------------------------------------------------------ ticket facial
def check_face_ticket(ticket: Optional[str], username: str, now: float | None = None) -> bool:
    """Valide le ticket émis par face-gate : signature, expiration, sujet, audience, usage unique.
    Consomme le ticket seulement s'il est valide (un ticket rejeté ne grille rien)."""
    if not ticket or not FACE_TICKET_SECRET:
        return False
    try:
        claims = jwt.decode(ticket, FACE_TICKET_SECRET, algorithms=["HS256"], audience="auth-service",
                            issuer="face-gate", options={"require": ["exp", "sub", "jti", "iss", "aud"]})
    except jwt.PyJWTError:
        return False
    if claims["sub"] != username:
        return False
    now = now if now is not None else time.time()
    with _lock:
        for jti in [j for j, exp in _used_tickets.items() if exp < now]:
            del _used_tickets[jti]
        if claims["jti"] in _used_tickets:
            return False
        _used_tickets[claims["jti"]] = float(claims["exp"]) + 5
    return True


# ------------------------------------------------------------------ initialisation
def seed_users(conn) -> None:
    """Comptes de démonstration. `demo-user` (portail de paiement) ne peut pas se connecter tant qu'aucun visage n'est inscrit :
    premier visage par `docker compose exec face-gate python enroll_cli.py <compte>` (accès à l'hôte), les suivants depuis le
    back-office. `admin` et `operator` (administration) se connectent par mot de passe seul ; `demo-bot` et `synthetic-probe`
    sont des comptes machine."""
    seed = [("demo-user", secret("DEMO_PASSWORD_FILE"), "user"),
            ("demo-bot", secret("BOT_PASSWORD_FILE"), "automation"),
            ("synthetic-probe", secret("PROBE_PASSWORD_FILE"), "probe"),
            ("admin", secret("ADMIN_PASSWORD_FILE"), "admin"),
            ("operator", secret("OPERATOR_PASSWORD_FILE"), "operator")]
    for username, password, role in seed:
        if not password:
            continue
        if not conn.execute("SELECT 1 FROM users WHERE username=%s", (username,)).fetchone():
            conn.execute("INSERT INTO users (username, password_hash, role) VALUES (%s,%s,%s)",
                         (username, hash_password(password), role))
            log.info("utilisateur de démonstration créé: %s", username)


@app.on_event("startup")
def startup() -> None:
    pool.open(wait=True, timeout=30)
    with pool.connection() as conn:
        seed_users(conn)


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


def client_ip(request: Request) -> str:
    # auth-service n'est joignable que par le WAF (réseau app) : l'en-tête est posé par lui.
    return (request.headers.get("x-forwarded-for", "") or (request.client.host if request.client else "")).split(",")[0].strip()


def audit(conn, actor: str, action: str, target: str = "", detail: dict | None = None, ip: str = "") -> None:
    conn.execute("INSERT INTO audit_log (actor, action, target, detail, ip) VALUES (%s,%s,%s,%s::jsonb,%s)",
                 (actor, action, target, json.dumps(detail or {}), ip))


# ------------------------------------------------------------------ authentification
class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=128)
    face_ticket: Optional[str] = Field(default=None, max_length=2048)


def locked(username: str) -> bool:
    now = time.time()
    with _lock:
        q = _failures[username]
        while q and now - q[0] > LOCK_WINDOW:
            q.popleft()
        return len(q) >= LOCK_AFTER


@app.post("/auth/token")
def token(creds: Credentials, request: Request):
    if locked(creds.username):
        LOGINS.labels("locked").inc()
        raise HTTPException(429, "Trop de tentatives, réessayez plus tard")
    try:
        with pool.connection() as conn:
            row = conn.execute(
                "SELECT u.password_hash, u.role, u.face_required, u.active, COALESCE(r.permissions, '{}') "
                "FROM users u LEFT JOIN roles r ON r.name = u.role WHERE u.username=%s", (creds.username,)).fetchone()
    except Exception as exc:
        log.error("base indisponible: %s", exc)
        raise HTTPException(503, "Service temporairement indisponible")

    stored = row[0] if row else DUMMY_HASH
    ok = verify_password(creds.password, stored) and row is not None and row[3]
    if not ok:
        with _lock:
            _failures[creds.username].append(time.time())
        LOGINS.labels("failure").inc()
        log.warning("echec authentification user=%s", creds.username)
        raise HTTPException(401, "Identifiants invalides")

    _, role, _face_flag, _, perms = row
    if needs_face(role, perms) and not check_face_ticket(creds.face_ticket, creds.username):
        # Mot de passe correct mais pas de preuve de reconnaissance faciale : refus (le mot de passe seul ne suffit pas).
        LOGINS.labels("face_required").inc()
        log.warning("refus: reconnaissance faciale requise user=%s", creds.username)
        raise HTTPException(403, "Reconnaissance faciale requise")

    now = int(time.time())
    LOGINS.labels("success").inc()
    return {"access_token": jwt.encode({"sub": creds.username, "role": role, "perms": sorted(perms), "iat": now,
                                        "exp": now + TOKEN_TTL, "iss": "resilience-auth"}, JWT_SECRET, algorithm="HS256"),
            "token_type": "bearer", "expires_in": TOKEN_TTL, "role": role, "perms": sorted(perms)}


# ------------------------------------------------------------------ habilitations
class Actor(BaseModel):
    sub: str
    role: str
    perms: list[str]


def current_actor(authorization: Optional[str] = Header(default=None)) -> Actor:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Authentification requise")
    try:
        c = jwt.decode(authorization[7:], JWT_SECRET, algorithms=["HS256"], issuer="resilience-auth",
                       options={"require": ["exp", "sub", "iss"]})
    except jwt.PyJWTError:
        raise HTTPException(401, "Jeton invalide ou expiré")
    return Actor(sub=c["sub"], role=c.get("role", ""), perms=c.get("perms", []))


def need(perm: str):
    """Dépendance FastAPI : permission portée par le JWT ET compte toujours actif en base (révocation immédiate)."""
    def dep(actor: Actor = Depends(current_actor)) -> Actor:
        if perm not in actor.perms or "backoffice:access" not in actor.perms:
            raise HTTPException(403, "Permission insuffisante")
        try:
            with pool.connection() as conn:
                row = conn.execute("SELECT u.active, COALESCE(r.permissions,'{}') FROM users u "
                                   "LEFT JOIN roles r ON r.name=u.role WHERE u.username=%s", (actor.sub,)).fetchone()
        except Exception:
            raise HTTPException(503, "Service temporairement indisponible")
        if not row or not row[0] or perm not in row[1]:
            raise HTTPException(403, "Permission insuffisante")
        return actor
    return dep


@app.get("/auth/me")
def me(actor: Actor = Depends(current_actor)):
    return actor


@app.get("/auth/admin/permissions")
def list_permissions(actor: Actor = Depends(need("backoffice:access"))):
    return [{"name": k, "description": v} for k, v in PERMISSIONS.items()]


class UserOut(BaseModel):
    username: str
    role: str
    active: bool
    face_required: bool
    faces: int
    created_at: str


@app.get("/auth/admin/users")
def list_users(actor: Actor = Depends(need("backoffice:users"))):
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT u.username, u.role, u.active, u.face_required, "
            "(SELECT count(*) FROM face_templates f WHERE f.username = u.username), u.created_at, "
            "COALESCE((SELECT permissions FROM roles r WHERE r.name = u.role), '{}') "
            "FROM users u ORDER BY u.username").fetchall()
    return [UserOut(username=r[0], role=r[1], active=r[2], face_required=needs_face(r[1], r[6]), faces=r[4],
                    created_at=r[5].isoformat()) for r in rows]


class NewUser(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=MIN_PASSWORD_LEN, max_length=128)
    role: str = Field(min_length=2, max_length=32)


def admin_perms(perms) -> set:
    """Seules les permissions d'ADMINISTRATION sont soumises à la règle anti-escalade : les droits de paiement d'un client ne donnent
    aucun pouvoir sur la plateforme, un administrateur peut donc créer des utilisateurs du portail sans les détenir lui-même."""
    return {p for p in perms if p.startswith("backoffice:")}


def assignable_role(conn, actor: Actor, role: str) -> None:
    if role in MACHINE_ROLES:
        raise HTTPException(422, "Les rôles « probe » et « automation » sont réservés aux comptes machine (sans visage)")
    row = conn.execute("SELECT permissions FROM roles WHERE name=%s", (role,)).fetchone()
    if not row:
        raise HTTPException(422, "Rôle inconnu")
    if not admin_perms(row[0]) <= set(actor.perms):       # pas d'escalade : on n'attribue que des droits d'administration qu'on détient
        raise HTTPException(403, "Vous ne pouvez pas attribuer un rôle plus puissant que le vôtre")


@app.post("/auth/admin/users", status_code=201)
def create_user(body: NewUser, request: Request, actor: Actor = Depends(need("backoffice:users"))):
    with pool.connection() as conn:
        assignable_role(conn, actor, body.role)
        if conn.execute("SELECT 1 FROM users WHERE username=%s", (body.username,)).fetchone():
            raise HTTPException(409, "Identifiant déjà utilisé")
        conn.execute("INSERT INTO users (username, password_hash, role) VALUES (%s,%s,%s)",
                     (body.username, hash_password(body.password), body.role))
        audit(conn, actor.sub, "user.create", body.username, {"role": body.role}, client_ip(request))
    ADMIN_ACTIONS.labels("user.create").inc()
    return {"username": body.username, "role": body.role}


class UserPatch(BaseModel):
    role: Optional[str] = Field(default=None, min_length=2, max_length=32)
    active: Optional[bool] = None
    face_required: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=MIN_PASSWORD_LEN, max_length=128)


@app.patch("/auth/admin/users/{username}")
def patch_user(username: str, body: UserPatch, request: Request, actor: Actor = Depends(need("backoffice:users"))):
    with pool.connection() as conn:
        cur = conn.execute("SELECT role, active, face_required FROM users WHERE username=%s", (username,)).fetchone()
        if not cur:
            raise HTTPException(404, "Utilisateur introuvable")
        if cur[0] in MACHINE_ROLES:
            raise HTTPException(403, "Compte machine : non modifiable ici")
        changes: dict = {}
        if body.face_required is False:
            raise HTTPException(422, "La reconnaissance faciale est obligatoire pour les utilisateurs du portail : elle ne se désactive pas (un rôle d'administration en est dispensé)")
        if username == actor.sub and (body.active is False or (body.role and body.role != cur[0])):
            raise HTTPException(422, "Vous ne pouvez pas réduire vos propres droits ou protections")
        if body.role and body.role != cur[0]:
            assignable_role(conn, actor, body.role)
            if cur[0] == "admin" and conn.execute(
                    "SELECT count(*) FROM users WHERE role='admin' AND active AND username<>%s", (username,)).fetchone()[0] == 0:
                raise HTTPException(409, "Il doit rester au moins un administrateur actif")
            conn.execute("UPDATE users SET role=%s WHERE username=%s", (body.role, username))
            changes["role"] = body.role
        if body.active is not None and body.active != cur[1]:
            if body.active is False and cur[0] == "admin" and conn.execute(
                    "SELECT count(*) FROM users WHERE role='admin' AND active AND username<>%s", (username,)).fetchone()[0] == 0:
                raise HTTPException(409, "Il doit rester au moins un administrateur actif")
            conn.execute("UPDATE users SET active=%s WHERE username=%s", (body.active, username))
            changes["active"] = body.active
        if body.password:
            conn.execute("UPDATE users SET password_hash=%s WHERE username=%s", (hash_password(body.password), username))
            changes["password"] = "réinitialisé"
            with _lock:
                _failures.pop(username, None)
        if changes:
            audit(conn, actor.sub, "user.update", username, changes, client_ip(request))
            ADMIN_ACTIONS.labels("user.update").inc()
    return {"username": username, "changes": list(changes)}


class RoleIn(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,31}$")
    description: str = Field(default="", max_length=200)
    permissions: list[str] = Field(max_length=len(PERMISSIONS))


def check_perms(actor: Actor, perms: list[str]) -> None:
    unknown = set(perms) - set(PERMISSIONS)
    if unknown:
        raise HTTPException(422, f"Permissions inconnues : {', '.join(sorted(unknown))}")
    if not admin_perms(perms) <= set(actor.perms):
        raise HTTPException(403, "Vous ne pouvez accorder que des permissions d'administration que vous détenez")


@app.get("/auth/admin/roles")
def list_roles(actor: Actor = Depends(need("backoffice:access"))):
    with pool.connection() as conn:
        rows = conn.execute("SELECT r.name, r.description, r.permissions, r.system, "
                            "(SELECT count(*) FROM users u WHERE u.role=r.name) FROM roles r ORDER BY r.name").fetchall()
    return [{"name": r[0], "description": r[1], "permissions": sorted(r[2]), "system": r[3], "users": r[4]} for r in rows]


@app.post("/auth/admin/roles", status_code=201)
def create_role(body: RoleIn, request: Request, actor: Actor = Depends(need("backoffice:roles"))):
    check_perms(actor, body.permissions)
    with pool.connection() as conn:
        if conn.execute("SELECT 1 FROM roles WHERE name=%s", (body.name,)).fetchone():
            raise HTTPException(409, "Ce rôle existe déjà")
        conn.execute("INSERT INTO roles (name, description, permissions) VALUES (%s,%s,%s)",
                     (body.name, body.description, sorted(set(body.permissions))))
        audit(conn, actor.sub, "role.create", body.name, {"permissions": sorted(set(body.permissions))}, client_ip(request))
    ADMIN_ACTIONS.labels("role.create").inc()
    return {"name": body.name}


@app.put("/auth/admin/roles/{name}")
def update_role(name: str, body: RoleIn, request: Request, actor: Actor = Depends(need("backoffice:roles"))):
    if body.name != name:
        raise HTTPException(422, "Le nom d'un rôle ne se change pas")
    check_perms(actor, body.permissions)
    with pool.connection() as conn:
        cur = conn.execute("SELECT system FROM roles WHERE name=%s", (name,)).fetchone()
        if not cur:
            raise HTTPException(404, "Rôle introuvable")
        if cur[0]:
            raise HTTPException(403, "Rôle système : non modifiable (créez un rôle personnalisé)")
        conn.execute("UPDATE roles SET description=%s, permissions=%s WHERE name=%s",
                     (body.description, sorted(set(body.permissions)), name))
        audit(conn, actor.sub, "role.update", name, {"permissions": sorted(set(body.permissions))}, client_ip(request))
    ADMIN_ACTIONS.labels("role.update").inc()
    return {"name": name}


@app.delete("/auth/admin/roles/{name}")
def delete_role(name: str, request: Request, actor: Actor = Depends(need("backoffice:roles"))):
    with pool.connection() as conn:
        cur = conn.execute("SELECT system FROM roles WHERE name=%s", (name,)).fetchone()
        if not cur:
            raise HTTPException(404, "Rôle introuvable")
        if cur[0]:
            raise HTTPException(403, "Rôle système : non supprimable")
        if conn.execute("SELECT count(*) FROM users WHERE role=%s", (name,)).fetchone()[0]:
            raise HTTPException(409, "Des utilisateurs portent encore ce rôle")
        conn.execute("DELETE FROM roles WHERE name=%s", (name,))
        audit(conn, actor.sub, "role.delete", name, {}, client_ip(request))
    ADMIN_ACTIONS.labels("role.delete").inc()
    return {"deleted": name}


@app.get("/auth/admin/audit")
def read_audit(limit: int = 100, actor: Actor = Depends(need("backoffice:audit"))):
    limit = max(1, min(limit, 500))
    with pool.connection() as conn:
        rows = conn.execute("SELECT ts, actor, action, target, detail, ip FROM audit_log ORDER BY id DESC LIMIT %s",
                            (limit,)).fetchall()
    return [{"ts": r[0].isoformat(), "actor": r[1], "action": r[2], "target": r[3], "detail": r[4], "ip": r[5]} for r in rows]


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
