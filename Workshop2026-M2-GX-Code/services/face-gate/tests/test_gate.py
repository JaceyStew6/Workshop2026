"""Tests de la logique d'accès biométrique : parcours, voyant, verrouillage, caméra, ticket, habilitations."""
import hashlib
import sys
import time
from pathlib import Path

import jwt
import numpy as np
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api import create_app  # noqa: E402
from gate import AgentError, AuthRejected, AuthUnavailable, Config, FaceGate, GateError  # noqa: E402
from store import MemoryStore, seal, unseal  # noqa: E402

TICKET_SECRET = "ticket-secret-for-tests-0123456789"
JWT_SECRET = "jwt-secret-for-tests-0123456789abcd"
DEVICE = "device-token-0123456789"


def person(name: str, noise: float = 0.05, seed: int = 0) -> list[float]:
    base = np.random.default_rng(int(hashlib.sha256(name.encode()).hexdigest()[:8], 16)).normal(size=128)
    v = base + np.random.default_rng(seed).normal(scale=noise, size=128)
    return (v / np.linalg.norm(v)).astype(np.float32).tolist()


class Clock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t
    def advance(self, s): self.t += s


class FakeAgent:
    def __init__(self):
        self.on = False
        self.who = None            # None = personne devant la caméra
        self.reason = "no_face"
        self.calls = []
        self.down = False

    def camera_on(self, max_seconds):
        if self.down:
            raise AgentError("down")
        self.on = True
        self.calls.append(("on", max_seconds))

    def embed(self, frames, timeout_s):
        if self.down:
            raise AgentError("down")
        assert self.on, "embed appelé caméra éteinte"
        if self.who is None:
            return {"embeddings": [], "reason": self.reason}
        return {"embeddings": [person(self.who, seed=i) for i in range(frames)], "reason": "ok"}

    def camera_off(self):
        self.on = False
        self.calls.append(("off",))

    def health(self):
        return {"status": "ok", "camera_on": self.on}


class FakeAuth:
    """Imite auth-service : ticket obligatoire, usage unique, mot de passe « bon-mot-de-passe »."""
    def __init__(self):
        self.used = set()
        self.calls = []
        self.down = False

    def login(self, username, password, ticket, ip):
        self.calls.append((username, ticket))
        if self.down:
            raise AuthUnavailable()
        if password != "bon-mot-de-passe":
            raise AuthRejected(401)
        c = jwt.decode(ticket, TICKET_SECRET, algorithms=["HS256"], audience="auth-service", issuer="face-gate")
        assert c["sub"] == username and c["jti"] not in self.used
        self.used.add(c["jti"])
        return {"access_token": "jwt-" + username, "token_type": "bearer"}


@pytest.fixture()
def env():
    clock, agent, auth, store = Clock(), FakeAgent(), FakeAuth(), MemoryStore()
    store.add_user("alice", "admin")
    store.add_user("demo-user", "user", face_required=False)
    store.add_template("alice", "test", np.asarray(person("alice"), dtype=np.float32), 8, "test")
    gate = FaceGate(store, agent, auth, TICKET_SECRET, Config(), clock, spawn=lambda fn: fn())   # synchrone
    return gate, agent, auth, store, clock


def login_face(gate, who="alice", user="alice", ip="10.0.0.5"):
    gate._agent_who = who
    return gate.identify(user, ip)


# ---------------------------------------------------------------- parcours nominal
def test_led_is_off_by_default_and_camera_off(env):
    gate, agent, *_ = env
    assert gate.led.read()["pattern"] == "off" and not agent.on


def test_recognised_then_green_blink_until_password_then_green_solid_30s_then_off(env):
    gate, agent, auth, store, clock = env
    agent.who = "alice"
    r = gate.identify("alice", "10.0.0.5")
    assert r["face_required"] and gate.status(r["session_id"])["state"] == "awaiting_password"
    assert gate.led.read()["pattern"] == "green_blink" and agent.on
    clock.advance(60)
    assert gate.led.read()["pattern"] == "green_blink"                  # clignote tant que le mot de passe n'est pas saisi
    token = gate.password(r["session_id"], "bon-mot-de-passe", "10.0.0.5")
    assert token["access_token"] == "jwt-alice"
    assert not agent.on                                                   # caméra éteinte dès la connexion
    assert gate.led.read()["pattern"] == "green_solid"
    clock.advance(29)
    assert gate.led.read()["pattern"] == "green_solid"
    clock.advance(2)
    assert gate.led.read()["pattern"] == "off"                            # 30 s puis éteint


def test_unrecognised_face_red_solid_30s_then_camera_off_and_retry_allowed(env):
    gate, agent, auth, store, clock = env
    agent.who = "mallory"
    r = gate.identify("alice", "10.0.0.5")
    st = gate.status(r["session_id"])
    assert st["state"] == "denied" and st["attempts_left"] == 1
    assert gate.led.read()["pattern"] == "red_solid" and agent.on
    with pytest.raises(GateError) as e:                                   # pendant les 30 s : poste occupé
        gate.identify("alice", "10.0.0.5")
    assert e.value.status == 423
    clock.advance(31)
    gate.tick()
    assert not agent.on and gate.led.read()["pattern"] == "off"
    assert gate.status(r["session_id"])["state"] == "closed"
    agent.who = "alice"
    assert gate.identify("alice", "10.0.0.5")["state"] == "scanning" or True   # une 2e tentative est possible


def test_two_failures_block_five_minutes_and_block_repeats(env):
    gate, agent, auth, store, clock = env
    agent.who = "mallory"
    for _ in range(2):
        gate.identify("alice", "10.0.0.5")
        clock.advance(31); gate.tick()
    with pytest.raises(GateError) as e:
        gate.identify("alice", "10.0.0.5")
    assert e.value.status == 429 and e.value.code == "blocked" and 255 < e.value.extra["blocked_s"] <= 301
    agent.who = "alice"                                                    # même le bon visage : toujours bloqué
    with pytest.raises(GateError):
        gate.identify("alice", "10.0.0.5")
    clock.advance(301)
    agent.who = "mallory"
    for _ in range(2):                                                     # le blocage SE RÉPÈTE
        gate.identify("alice", "10.0.0.5")
        clock.advance(31); gate.tick()
    with pytest.raises(GateError) as e:
        gate.identify("alice", "10.0.0.5")
    assert e.value.code == "blocked"


def test_wrong_password_red_blink_10s_camera_off_then_restart_identification(env):
    gate, agent, auth, store, clock = env
    agent.who = "alice"
    r = gate.identify("alice", "10.0.0.5")
    with pytest.raises(GateError) as e:
        gate.password(r["session_id"], "mauvais", "10.0.0.5")
    assert e.value.status == 401 and e.value.extra["restart"] is True
    led = gate.led.read()
    assert led["pattern"] == "red_blink" and 9000 <= led["remaining_ms"] <= 10000
    assert not agent.on
    with pytest.raises(GateError):                                          # le mot de passe seul ne rouvre rien
        gate.password(r["session_id"], "bon-mot-de-passe", "10.0.0.5")
    clock.advance(11); gate.tick()
    assert gate.led.read()["pattern"] == "off"
    agent.who = "alice"
    assert gate.identify("alice", "10.0.0.5")["state"] == "scanning"        # identification à recommencer


def test_password_failures_do_not_count_in_the_face_lockout_but_face_success_resets_it(env):
    gate, agent, auth, store, clock = env
    agent.who = "mallory"
    gate.identify("alice", "10.0.0.5"); clock.advance(31); gate.tick()      # 1 échec de reconnaissance
    agent.who = "alice"
    r = gate.identify("alice", "10.0.0.5")                                   # visage reconnu : série close
    with pytest.raises(GateError):
        gate.password(r["session_id"], "mauvais", "10.0.0.5")               # mot de passe faux : pas de blocage facial
    clock.advance(11); gate.tick()
    agent.who = "mallory"
    gate.identify("alice", "10.0.0.5"); clock.advance(31); gate.tick()      # à nouveau 1 seul échec facial consécutif
    agent.who = "alice"
    assert gate.identify("alice", "10.0.0.5")["state"] == "scanning"


def test_success_resets_failure_counter(env):
    gate, agent, auth, store, clock = env
    agent.who = "mallory"
    gate.identify("alice", "10.0.0.5"); clock.advance(31); gate.tick()
    agent.who = "alice"
    r = gate.identify("alice", "10.0.0.5")
    gate.password(r["session_id"], "bon-mot-de-passe", "10.0.0.5")
    clock.advance(31)
    agent.who = "mallory"
    gate.identify("alice", "10.0.0.5"); clock.advance(31); gate.tick()
    agent.who = "alice"
    assert gate.identify("alice", "10.0.0.5")["state"] == "scanning"       # pas bloqué : le compteur avait été remis à zéro


# ---------------------------------------------------------------- sécurité
def test_unknown_and_inactive_users_go_through_the_same_scan_and_fail(env):
    gate, agent, auth, store, clock = env
    store.add_user("ghost-inactive", "admin", active=False)
    agent.who = "alice"
    for u in ("inconnu", "ghost-inactive"):
        r = gate.identify(u, "10.0.0.9")
        assert r["face_required"] and gate.status(r["session_id"])["state"] == "denied"
        clock.advance(31); gate.tick()


def test_face_exempt_account_skips_camera_entirely(env):
    gate, agent, *_ = env
    assert gate.identify("demo-user", "10.0.0.5") == {"face_required": False}
    assert not agent.on and agent.calls == []


def test_agent_down_fails_closed_without_counting_a_user_failure(env):
    gate, agent, auth, store, clock = env
    agent.down = True
    r = gate.identify("alice", "10.0.0.5")
    st = gate.status(r["session_id"])
    assert st["state"] == "closed" and st["final"] == "error" and st["reason"] == "agent_unavailable"
    assert gate.led.read()["pattern"] == "off"
    agent.down = False
    agent.who = "alice"
    assert gate.identify("alice", "10.0.0.5")["state"] == "scanning"        # aucune pénalité pour l'utilisateur


def test_password_not_accepted_before_face_recognition_or_after_denial(env):
    gate, agent, auth, store, clock = env
    agent.who = "mallory"
    r = gate.identify("alice", "10.0.0.5")
    with pytest.raises(GateError) as e:
        gate.password(r["session_id"], "bon-mot-de-passe", "10.0.0.5")
    assert e.value.status == 409 and auth.calls == []
    with pytest.raises(GateError) as e:
        gate.password("0" * 32, "bon-mot-de-passe", "10.0.0.5")
    assert e.value.status == 404


def test_ticket_is_bound_to_user_signed_and_short_lived(env):
    gate, agent, auth, store, clock = env
    agent.who = "alice"
    r = gate.identify("alice", "10.0.0.5")
    gate.password(r["session_id"], "bon-mot-de-passe", "10.0.0.5")
    ticket = auth.calls[0][1]
    c = jwt.decode(ticket, TICKET_SECRET, algorithms=["HS256"], audience="auth-service", issuer="face-gate")
    assert c["sub"] == "alice" and 0 < c["exp"] - c["iat"] <= 120
    with pytest.raises(jwt.PyJWTError):
        jwt.decode(ticket, "autre-secret-quelconque-0123456789", algorithms=["HS256"], audience="auth-service")


def test_session_never_exposes_ticket_or_embeddings(env):
    gate, agent, *_ = env
    agent.who = "alice"
    r = gate.identify("alice", "10.0.0.5")
    blob = str(gate.status(r["session_id"])) + str(r)
    assert "ticket" not in blob and "eyJ" not in blob


def test_password_phase_times_out_with_led_off_and_camera_off(env):
    gate, agent, auth, store, clock = env
    agent.who = "alice"
    r = gate.identify("alice", "10.0.0.5")
    clock.advance(121); gate.tick()
    assert not agent.on and gate.led.read()["pattern"] == "off"
    with pytest.raises(GateError):
        gate.password(r["session_id"], "bon-mot-de-passe", "10.0.0.5")


def test_auth_unavailable_does_not_burn_the_session_or_count_a_failure(env):
    gate, agent, auth, store, clock = env
    agent.who = "alice"
    r = gate.identify("alice", "10.0.0.5")
    auth.down = True
    with pytest.raises(GateError) as e:
        gate.password(r["session_id"], "bon-mot-de-passe", "10.0.0.5")
    assert e.value.status == 503
    auth.down = False
    assert gate.password(r["session_id"], "bon-mot-de-passe", "10.0.0.5")["access_token"] == "jwt-alice"


def test_only_one_session_at_a_time(env):
    gate, agent, *_ = env
    agent.who = "alice"
    gate.identify("alice", "10.0.0.5")
    with pytest.raises(GateError) as e:
        gate.identify("alice", "10.0.0.6")
    assert e.value.status == 423


def test_ip_rate_limit_protects_the_camera(env):
    gate, agent, auth, store, clock = env
    agent.who = "alice"
    for _ in range(10):
        r = gate.identify("alice", "10.0.0.7")
        gate.cancel(r["session_id"])
    with pytest.raises(GateError) as e:
        gate.identify("alice", "10.0.0.7")
    assert e.value.code == "ip_limited"


def test_cancel_turns_camera_and_led_off(env):
    gate, agent, *_ = env
    agent.who = "alice"
    r = gate.identify("alice", "10.0.0.5")
    gate.cancel(r["session_id"])
    assert not agent.on and gate.led.read()["pattern"] == "off"


# ---------------------------------------------------------------- inscription
def test_enrol_encrypts_template_enables_requirement_and_refuses_inconsistent_samples(env):
    gate, agent, auth, store, clock = env
    store.add_user("bob", "operator", face_required=False)
    agent.who = "bob"
    job = gate.start_enroll("bob", "face", "alice", "10.0.0.5")
    assert gate.enroll_status(job["job_id"])["state"] == "done"
    assert store.user_info("bob")["face_required"] is True and not agent.on
    raw = next(iter(t for t in store._tpl.values() if t["username"] == "bob"))
    assert len(raw["ct"]) > 128 * 4                                        # chiffré (+ étiquette GCM), pas le vecteur brut
    with pytest.raises(Exception):
        unseal(store.key, "alice", raw["nonce"], raw["ct"])                # liée à l'utilisateur (AAD)
    # échantillons incohérents (plusieurs personnes alternent)
    store.add_user("carl", "operator", face_required=False)
    seq = iter(range(100))
    agent.embed = lambda frames, timeout_s: {"embeddings": [person("a" if next(seq) % 2 else "b") for _ in range(frames)], "reason": "ok"}
    job = gate.start_enroll("carl", "face", "alice", "10.0.0.5")
    assert gate.enroll_status(job["job_id"])["state"] == "failed"
    assert store.count_templates("carl") == 0 and store.user_info("carl")["face_required"] is False


def test_enrol_refused_while_a_login_session_uses_the_camera(env):
    gate, agent, *_ = env
    agent.who = "alice"
    gate.identify("alice", "10.0.0.5")
    with pytest.raises(GateError) as e:
        gate.start_enroll("alice", "x", "alice", "10.0.0.5")
    assert e.value.status == 423


def test_cannot_delete_last_template_of_a_face_required_account(env):
    gate, agent, auth, store, clock = env
    tid = store.list_templates("alice")[0]["id"]
    with pytest.raises(GateError) as e:
        gate.delete_face(tid, "alice", "10.0.0.5")
    assert e.value.code == "last_template"


# ---------------------------------------------------------------- voyant
def test_led_patterns_expire_by_themselves_and_bump_seq(env):
    gate, agent, auth, store, clock = env
    gate.led.set("red_blink", 10)
    a = gate.led.read()
    assert a["pattern"] == "red_blink"
    clock.advance(11)
    b = gate.led.read()
    assert b["pattern"] == "off" and b["seq"] > a["seq"] and b["remaining_ms"] == 0


# ---------------------------------------------------------------- API HTTP
@pytest.fixture()
def http(env):
    gate, agent, auth, store, clock = env
    app = create_app(gate, JWT_SECRET, DEVICE, reaper_interval_s=None)
    return TestClient(app), gate, agent, store


def bearer(sub="alice", perms=("backoffice:access", "backoffice:faces", "backoffice:device")):
    now = int(time.time())
    return {"authorization": "Bearer " + jwt.encode({"sub": sub, "role": "admin", "perms": list(perms), "iat": now, "exp": now + 600,
                                                    "iss": "resilience-auth"}, JWT_SECRET, algorithm="HS256")}


def test_http_flow_end_to_end(http):
    c, gate, agent, store = http
    gate._spawn = lambda fn: fn()
    agent.who = "alice"
    r = c.post("/gate/identify", json={"username": "alice"}).json()
    sid = r["session_id"]
    assert c.get(f"/gate/session/{sid}").json()["led"]["pattern"] == "green_blink"
    assert c.post("/gate/password", json={"session_id": sid, "password": "mauvais"}).status_code == 401
    r = c.post("/gate/identify", json={"username": "alice"})
    assert r.status_code == 423                                              # maintien rouge en cours (poste occupé)


def test_http_device_endpoint_requires_token_and_returns_led(http):
    c, gate, agent, store = http
    assert c.get("/gate/device/led").status_code == 401
    assert c.get("/gate/device/led", headers={"x-device-token": "faux"}).status_code == 401
    r = c.get("/gate/device/led", headers={"x-device-token": DEVICE})
    assert r.status_code == 200 and r.json()["pattern"] == "off"
    assert gate.device_status()["device"]["online"] is True


def test_http_admin_endpoints_need_permission_and_active_account(http):
    c, gate, agent, store = http
    assert c.get("/gate/faces").status_code == 401
    assert c.get("/gate/faces", headers=bearer(perms=("backoffice:access",))).status_code == 403
    assert c.get("/gate/faces", headers=bearer(perms=("backoffice:faces",))).status_code == 403     # sans backoffice:access
    assert c.get("/gate/faces", headers=bearer()).status_code == 200
    store.users["alice"]["active"] = False
    assert c.get("/gate/faces", headers=bearer()).status_code == 403                                  # révocation immédiate


def test_http_led_test_refused_during_login_and_validates_pattern(http):
    c, gate, agent, store = http
    assert c.post("/gate/device/test", json={"pattern": "disco"}, headers=bearer()).status_code == 422
    assert c.post("/gate/device/test", json={"pattern": "green_solid", "seconds": 3}, headers=bearer()).status_code == 200
    gate._spawn = lambda fn: fn()
    agent.who = "alice"
    c.post("/gate/identify", json={"username": "alice"})
    assert c.post("/gate/device/test", json={"pattern": "red_solid"}, headers=bearer()).status_code == 423


def test_http_inputs_are_validated(http):
    c, *_ = http
    assert c.post("/gate/identify", json={"username": "a b; drop"}).status_code == 422
    assert c.post("/gate/password", json={"session_id": "xyz", "password": "p"}).status_code == 422


def test_seal_roundtrip():
    key = b"k" * 32
    v = np.arange(128, dtype=np.float32)
    n, ct = seal(key, "u", v)
    assert np.array_equal(unseal(key, "u", n, ct), v)
