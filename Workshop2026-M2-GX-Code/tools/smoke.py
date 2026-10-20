#!/usr/bin/env python3
"""Smoke test métier (bibliothèque standard uniquement) : devis, connexion, paiement, relecture.

  python3 tools/smoke.py --base http://192.168.137.1
Lit le mot de passe de démonstration dans .secrets/demo_password. Code de sortie 0 si tout passe.
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def call(base, method, path, body=None, token=None, timeout=5):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"content-type": "application/json", **({"authorization": f"Bearer {token}"} if token else {})})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}"), time.perf_counter() - t0
    except urllib.error.HTTPError as e:
        return e.code, {}, time.perf_counter() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--secret-file", default=str(Path(__file__).resolve().parents[1] / ".secrets" / "demo_password"))
    a = ap.parse_args()
    if not Path(a.secret_file).is_file():
        sys.exit(f"Secret introuvable : {a.secret_file} (lancez tools/render_secrets.sh ou passez --secret-file)")
    pwd = Path(a.secret_file).read_text().strip()
    ok = True

    def check(name, cond, ms, extra=""):
        nonlocal ok
        ok &= bool(cond)
        print(f"  [{'OK' if cond else 'KO'}] {name:<22} {ms*1000:6.0f} ms {extra}")

    s, d, t = call(a.base, "GET", "/api/fees/quote?amount=100")
    check("devis public", s == 200, t, f"frais={d.get('fee')}")
    s, d, t = call(a.base, "POST", "/auth/token", {"username": "demo-user", "password": pwd})
    check("connexion", s == 200, t)
    token = d.get("access_token")
    s, d, t = call(a.base, "POST", "/api/payments", {"from": "ACC-DEMO-1", "to": "ACC-DEMO-2", "amount": "1.00"}, token)
    check("paiement", s == 201 and d.get("status") == "COMPLETED", t, d.get("id", ""))
    if s == 201:
        s, d2, t = call(a.base, "GET", f"/api/payments/{d['id']}", token=token)
        check("relecture", s == 200 and d2.get("status") == "COMPLETED", t)
    print("SMOKE", "OK" if ok else "ECHEC")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
