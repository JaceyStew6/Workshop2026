#!/usr/bin/env python3
"""Scénario d'attaque n°2 (optionnel) : INJECTION SQL + SCAN, bloquées par le WAF et tracées au SIEM.

  python attack_sqli.py --target http://192.168.137.1 --i-own-this-lab

But pédagogique : montrer la différence entre RESTAURER LA DISPONIBILITÉ (scénario flood) et CONTENIR
UNE TENTATIVE DE COMPROMISSION. Ici le bon résultat n'est pas un redémarrage : ce sont des 403 du WAF,
des alertes SIEM (WafSignatureBlocks) et une escalade humaine pour investigation.

Mêmes garde-fous de périmètre que attack_flood.py. Les charges sont des CLASSIQUES inoffensives
(détection, aucune exfiltration réelle : l'API ne concatène jamais de SQL).
"""
import argparse
import sys
import time

import httpx

from attack_flood import check_scope

PAYLOADS = [
    ("GET", "/api/fees/quote", {"amount": "1' OR '1'='1"}),
    ("GET", "/api/fees/quote", {"amount": "1 UNION SELECT username,password_hash FROM users--"}),
    ("GET", "/api/fees/quote", {"amount": "1;SELECT pg_sleep(5)"}),
    ("GET", "/api/payments", {"q": "x'; DROP TABLE accounts;--"}),
    ("GET", "/api/fees/quote", {"amount": "<script>alert(1)</script>"}),
    ("GET", "/api/../../etc/passwd", {}),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--source-ip", help="IP locale à utiliser (laboratoire multi-IP)")
    ap.add_argument("--delay", type=float, default=0.2, help="pause entre requêtes (s)")
    ap.add_argument("--i-own-this-lab", action="store_true")
    ap.add_argument("--allow-loopback", action="store_true")
    a = ap.parse_args()
    if not a.i_own_this_lab:
        sys.exit("REFUS : ajoutez --i-own-this-lab (cible = votre propre plateforme de laboratoire).")
    print(f"cible validée : {check_scope(a.target, a.allow_loopback)}")
    results = {}
    transport = httpx.HTTPTransport(local_address=a.source_ip) if a.source_ip else None
    with httpx.Client(base_url=a.target, timeout=5.0, transport=transport) as c:
        for _ in range(a.rounds):
            for method, path, params in PAYLOADS:
                try:
                    r = c.request(method, path, params=params)
                    results[r.status_code] = results.get(r.status_code, 0) + 1
                except httpx.HTTPError as exc:
                    results[type(exc).__name__] = results.get(type(exc).__name__, 0) + 1
                time.sleep(a.delay)
        r = c.get("/api/fees/quote", params={"amount": 5}, headers={"User-Agent": "sqlmap/1.7.2#stable"})
        results[f"scanner-ua:{r.status_code}"] = 1
    print("codes de réponse:", results)


if __name__ == "__main__":
    main()
