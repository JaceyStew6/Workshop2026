"""auth-service : ticket facial obligatoire pour les comptes `face_required`, usage unique, permissions dans le JWT."""
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as auth  # noqa: E402

TICKET_SECRET = "ticket-secret-for-tests-0123456789"
JWT_SECRET = "jwt-secret-for-tests-0123456789abcd"


class FakeConn:
    def __init__(self, users): self.users = users
    def execute(self, sql, params=()):
        class R:
            def __init__(s, row): s.row = row
            def fetchone(s): return s.row
            def fetchall(s): return [s.row] if s.row else []
        if "FROM users u LEFT JOIN roles" in sql and "password_hash" in sql:
            return R(self.users.get(params[0]))
        return R(None)


class FakePool:
    def __init__(self, users): self.users = users
    @contextmanager
    def connection(self, timeout=None):
        yield FakeConn(self.users)
    def open(self, **kw): pass


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(auth, "JWT_SECRET", JWT_SECRET)
    monkeypatch.setattr(auth, "FACE_TICKET_SECRET", TICKET_SECRET)
    users = {
        "alice": (auth.hash_password("bon-mot-de-passe"), "user", True, True, ["payments:create", "payments:read"]),     # utilisateur du portail
        "root": (auth.hash_password("root-password-ok"), "admin", False, True, ["backoffice:access", "backoffice:users"]),   # administration
        "demo-user": (auth.hash_password("demo-password-ok"), "user", False, True, ["payments:create", "payments:read"]),   # humain, drapeau à False
        "demo-bot": (auth.hash_password("bot-password-ok"), "automation", False, True, ["payments:create", "payments:read"]),
        "gone": (auth.hash_password("bon-mot-de-passe"), "user", False, False, []),
    }
    monkeypatch.setattr(auth, "pool", FakePool(users))
    auth._failures.clear()
    auth._used_tickets.clear()
    monkeypatch.setattr(auth, "startup", lambda: None)
    app = auth.app
    app.router.on_startup.clear()
    return TestClient(app)


def ticket(sub="alice", secret=TICKET_SECRET, ttl=120, aud="auth-service", iss="face-gate", jti="j1"):
    now = int(time.time())
    return jwt.encode({"iss": iss, "aud": aud, "sub": sub, "jti": jti, "iat": now, "exp": now + ttl}, secret, algorithm="HS256")


def login(c, user="alice", pw="bon-mot-de-passe", t=None):
    body = {"username": user, "password": pw}
    if t is not None:
        body["face_ticket"] = t
    return c.post("/auth/token", json=body)


def test_face_required_account_cannot_get_a_token_with_password_alone(client):
    r = login(client)
    assert r.status_code == 403 and "access_token" not in r.text


def test_valid_ticket_gives_token_with_permissions(client):
    r = login(client, t=ticket())
    assert r.status_code == 200
    claims = jwt.decode(r.json()["access_token"], JWT_SECRET, algorithms=["HS256"], issuer="resilience-auth")
    assert claims["perms"] == ["payments:create", "payments:read"] and claims["role"] == "user"


def test_ticket_is_single_use(client):
    t = ticket(jti="once")
    assert login(client, t=t).status_code == 200
    assert login(client, t=t).status_code == 403


@pytest.mark.parametrize("bad", [
    lambda: ticket(secret="x" * 40),            # mauvaise signature
    lambda: ticket(sub="mallory"),              # ticket d'un autre compte
    lambda: ticket(ttl=-5),                     # expiré
    lambda: ticket(aud="autre"),
    lambda: ticket(iss="pirate"),
    lambda: "pas-un-jwt",
])
def test_invalid_tickets_are_refused(client, bad):
    assert login(client, t=bad()).status_code == 403


def test_rejected_ticket_is_not_consumed(client):
    t = ticket(jti="keep")
    assert login(client, pw="mauvais", t=t).status_code == 401           # mot de passe faux : le ticket reste valide
    assert login(client, t=t).status_code == 200


def test_portal_user_needs_a_ticket_whatever_its_flag(client):
    assert login(client, "demo-user", "demo-password-ok").status_code == 403       # le portail de paiement aussi
    r = login(client, "demo-user", "demo-password-ok", t=ticket(sub="demo-user", jti="portail"))
    assert r.status_code == 200 and r.json()["perms"] == ["payments:create", "payments:read"]


def test_machine_and_administration_accounts_log_in_with_a_password_alone(client):
    r = login(client, "demo-bot", "bot-password-ok")
    assert r.status_code == 200 and r.json()["role"] == "automation"
    r = login(client, "root", "root-password-ok")                                   # administration : pas de visage
    assert r.status_code == 200 and "backoffice:users" in r.json()["perms"]
    assert auth.needs_face("user", ["payments:create"]) and not auth.needs_face("admin", ["backoffice:access"])
    assert auth.needs_face("customer", []) and not auth.needs_face("custom", ["backoffice:access"])


def test_machine_roles_cannot_be_assigned_to_humans_through_the_api():
    actor = auth.Actor(sub="adm", role="admin", perms=list(auth.PERMISSIONS))

    class C:
        def execute(self, *a, **k):
            raise AssertionError("ne doit même pas interroger la base")
    for role in ("probe", "automation"):
        with pytest.raises(Exception) as e:
            auth.assignable_role(C(), actor, role)
        assert getattr(e.value, "status_code", None) == 422


def test_inactive_account_is_refused_like_a_wrong_password(client):
    assert login(client, "gone").status_code == 401


def test_unknown_user_and_wrong_password_look_the_same(client):
    a, b = login(client, "inconnu", "x" * 12), login(client, "alice", "mauvais-mdp-12")
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_cannot_grant_permissions_one_does_not_hold():
    actor = auth.Actor(sub="op", role="operator", perms=["backoffice:access", "backoffice:faces"])
    with pytest.raises(Exception) as e:
        auth.check_perms(actor, ["backoffice:users"])
    assert getattr(e.value, "status_code", None) == 403
    with pytest.raises(Exception) as e:
        auth.check_perms(actor, ["inexistante"])
    assert getattr(e.value, "status_code", None) == 422
    auth.check_perms(actor, ["backoffice:faces"])
    auth.check_perms(actor, ["payments:create"])      # droits de paiement : ne donnent aucun pouvoir d'administration


def test_admin_api_needs_permission_in_jwt(client):
    now = int(time.time())
    tok = jwt.encode({"sub": "demo-user", "role": "user", "perms": ["payments:create"], "iat": now, "exp": now + 60,
                      "iss": "resilience-auth"}, JWT_SECRET, algorithm="HS256")
    assert client.get("/auth/admin/users", headers={"authorization": "Bearer " + tok}).status_code == 403
    assert client.get("/auth/admin/users").status_code == 401
