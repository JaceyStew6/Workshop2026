import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

from engine import (CONTAINED, ESCALATED, RECOVERED, Engine, IncidentIn, ProbeResult, Settings)
from main import create_app

ATTACKER = "192.168.137.20"


class FakeWaf:
    def __init__(self, refuse=()):
        self.bans, self.refuse = [], set(refuse)

    async def ban(self, ip, ttl, reason, incident_id):
        if ip in self.refuse:
            return False, "refusé"
        self.bans.append((ip, ttl, incident_id))
        return True, "ok"


class FakeSystem:
    """Simule le service métier : `recovers_on` décrit ce qui le répare (ban, restart, rien)."""

    def __init__(self, recovers_on="ban", ledger_ok=True, restart_ok=True):
        self.recovers_on, self.ledger_ok, self.restart_ok = recovers_on, ledger_ok, restart_ok
        self.degraded = True
        self.restarts, self.waf = [], None

    # ControllerPort
    async def restart(self, target):
        self.restarts.append(target)
        if self.restart_ok and self.recovers_on in ("restart", "ban_and_restart"):
            self.degraded = False
        return self.restart_ok, "ok" if self.restart_ok else "docker KO"

    async def healthy(self, target):
        return not self.degraded

    # ProbePort
    async def quick(self):
        if self.recovers_on == "ban" and self.waf and self.waf.bans:
            self.degraded = False
        return not self.degraded

    async def full(self):
        await self.quick()
        ok = (not self.degraded) and self.ledger_ok
        return ProbeResult(ok, [{"step": "payment", "ok": not self.degraded}, {"step": "ledger", "ok": self.ledger_ok}])


def make(system=None, waf=None, **kw):
    waf = waf or FakeWaf()
    system = system or FakeSystem()
    system.waf = waf
    st = Settings(allowed_targets={"payment-api": "c-payment"}, never_ban={"192.168.137.1"}, health_wait=0.3,
                  restart_wait=0.3, verify_timeout=0.3, poll=0.02, max_restarts=2, restart_window=60, **kw)
    return Engine(st, waf, system, system), waf, system


def inc(cls="availability", ips=None, iid="inc-test-1"):
    return IncidentIn(incident_id=iid, target_service="payment-api", suspected_class=cls, anomaly_score=0.9,
                      source="ml-detector", evidence={"req_rate_per_ip": ips if ips is not None else {ATTACKER: 400.0}})


async def run(engine, i):
    created = engine.submit(i)[0]
    return await engine.wait(created.id, 5)


def actions(i):
    return [s["action"] for s in i.steps]


@pytest.mark.asyncio
async def test_ban_alone_recovers_without_restart():
    e, waf, sys_ = make(FakeSystem("ban"))
    r = await run(e, inc())
    assert r.state == RECOVERED
    assert waf.bans[0][0] == ATTACKER and sys_.restarts == []


@pytest.mark.asyncio
async def test_restart_when_ban_is_not_enough():
    e, waf, sys_ = make(FakeSystem("restart"))
    r = await run(e, inc())
    assert r.state == RECOVERED and sys_.restarts == ["c-payment"]
    assert actions(r)[:2] == ["BAN_IP", "ASSESS"] or "RESTART_SERVICE" in actions(r)


@pytest.mark.asyncio
async def test_not_recovered_if_ledger_inconsistent():
    """Un conteneur qui répond ne suffit pas : si les données sont incohérentes, ce n'est pas résolu."""
    e, _, _ = make(FakeSystem("ban", ledger_ok=False))
    r = await run(e, inc())
    assert r.state == ESCALATED


@pytest.mark.asyncio
async def test_escalates_when_nothing_works():
    e, _, sys_ = make(FakeSystem("nothing"))
    r = await run(e, inc())
    assert r.state == ESCALATED
    assert len(sys_.restarts) <= 2


@pytest.mark.asyncio
async def test_compromise_is_contained_never_restarted():
    e, waf, sys_ = make(FakeSystem("ban"))
    r = await run(e, inc("compromise"))
    assert r.state == CONTAINED and sys_.restarts == []
    assert "RESTART_SERVICE" not in actions(r)


@pytest.mark.asyncio
async def test_unknown_class_takes_no_action():
    e, waf, sys_ = make()
    r = await run(e, inc("unknown"))
    assert r.state == ESCALATED and waf.bans == [] and sys_.restarts == []


@pytest.mark.asyncio
async def test_protected_ip_is_never_banned():
    e, waf, _ = make(FakeSystem("restart"))
    r = await run(e, inc(ips={"192.168.137.1": 900.0}))
    assert waf.bans == []                                # PC Hôte protégé par le moteur lui-même


@pytest.mark.asyncio
async def test_low_rate_source_not_banned():
    e, waf, _ = make(FakeSystem("restart"))
    await run(e, inc(ips={ATTACKER: 5.0}))
    assert waf.bans == []


@pytest.mark.asyncio
async def test_waf_refusal_does_not_block_recovery_path():
    e, waf, _ = make(FakeSystem("restart"), FakeWaf(refuse=[ATTACKER]))
    r = await run(e, inc())
    assert r.state == RECOVERED and any(s["action"] == "BAN_IP" and not s["ok"] for s in r.steps)


@pytest.mark.asyncio
async def test_duplicate_alert_is_absorbed():
    e, _, _ = make(FakeSystem("restart"))
    a, created_a = e.submit(inc(iid="inc-aaa-1"))
    b, created_b = e.submit(inc(iid="inc-bbb-2"))
    assert created_a and not created_b and a.id == b.id
    await e.wait(a.id, 5)


@pytest.mark.asyncio
async def test_unknown_target_rejected():
    e, _, _ = make()
    with pytest.raises(ValueError):
        e.submit(IncidentIn(incident_id="inc-x-1", target_service="postgres", suspected_class="availability"))


@pytest.mark.asyncio
async def test_restart_budget_is_enforced_across_incidents():
    e, _, sys_ = make(FakeSystem("nothing"))
    for n in range(4):
        await run(e, inc(iid=f"inc-loop-{n}"))
    assert len(sys_.restarts) == 2                       # max_restarts=2 dans la fenêtre, même avec 4 incidents


# ------------------------------------------------------------------ API
def client(system=None):
    system = system or FakeSystem("ban")
    waf = FakeWaf()
    system.waf = waf
    st = Settings(allowed_targets={"payment-api": "c-payment"}, health_wait=0.2, restart_wait=0.2,
                  verify_timeout=0.2, poll=0.02)
    return TestClient(create_app(st, waf, system, system, "s3cret-token")), waf


BODY = {"incident_id": "inc-api-1", "target_service": "payment-api", "suspected_class": "availability",
        "anomaly_score": 0.9, "source": "ml-detector", "evidence": {"req_rate_per_ip": {ATTACKER: 400}}}


def test_api_requires_token():
    c, _ = client()
    with c:
        assert c.post("/v1/incidents", json=BODY).status_code == 401
        assert c.post("/v1/incidents", json=BODY, headers={"X-Service-Token": "wrong"}).status_code == 401
        assert c.post("/v1/incidents", json=BODY, headers={"X-Service-Token": "s3cret-token"}).status_code == 202


@pytest.mark.parametrize("patch", [
    {"target_service": "postgres"},                       # cible hors liste
    {"incident_id": "x; rm -rf /"},                       # identifiant malformé
    {"suspected_class": "restart-everything"},            # classe hors énumération
    {"anomaly_score": 7},
    {"evidence": {"blob": "a" * 5000}},                   # preuve démesurée
])
def test_api_rejects_malformed_or_dangerous_input(patch):
    c, _ = client()
    with c:
        r = c.post("/v1/incidents", json={**BODY, **patch}, headers={"X-Service-Token": "s3cret-token"})
        assert r.status_code in (400, 422)


def test_api_incident_flow_and_state():
    c, waf = client()
    with c:
        assert c.post("/v1/incidents", json=BODY, headers={"X-Service-Token": "s3cret-token"}).json()["created"]
        for _ in range(100):
            d = c.get("/v1/incidents/inc-api-1").json()
            if d["state"] in ("RECOVERED", "ESCALATED", "CONTAINED"):
                break
            import time; time.sleep(0.05)
        assert d["state"] == "RECOVERED"
        assert [t["state"] for t in d["transitions"]][:3] == ["DETECTED", "DECIDING", "REMEDIATING"]
        assert c.get("/v1/state").status_code == 200
