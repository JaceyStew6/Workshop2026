"""Générateur de trafic NORMAL : fournit les données d'entraînement et le fond de la démo.

  python normal_traffic.py --base http://192.168.137.1 --minutes 120 --sources 5

Simule plusieurs clients à partir de plusieurs IP sources locales (--source-ips, alias IP du PC)
ou, à défaut, depuis l'IP unique de la machine, avec
temps de réflexion aléatoires et RAFALES LÉGITIMES (débit x2-3 pendant 20-40 s) : sans elles,
le modèle apprend qu'un pic de charge est anormal et déclenche des faux positifs en démo.

Essai sur UN SEUL POSTE (sans 2e PC) : --source-ips ne suffit pas à distinguer les sources pour le
WAF (Docker Desktop masque l'IP réelle). --spoof-ips (même format, une IP par source) simule des
identités d'utilisateurs distinctes via X-Forwarded-For ; le WAF ne les croit QUE si TRUSTED_PROXIES
(.env) est réglé sur le sous-réseau du réseau `edge` (voir README, « Essai sur un seul poste »).
Sans --spoof-ips, comportement inchangé.

Périmètre : cibler UNIQUEMENT la plateforme de l'équipe (réseau du hotspot). Aucune donnée réelle.
"""
import argparse
import asyncio
import random
import time

import httpx


async def client_loop(base: str, ip: str, stop_at: float, burst_until: list, user: str, pwd: str, spoof_ip: str = None):
    # Chaque "source" a sa propre adresse IP locale (alias) : le WAF voit de vraies IP distinctes
    # (sauf sous Docker Desktop : voir --spoof-ips / docstring).
    transport = httpx.AsyncHTTPTransport(local_address=ip)
    xff = {"X-Forwarded-For": spoof_ip} if spoof_ip else {}
    async with httpx.AsyncClient(base_url=base, transport=transport, timeout=5.0, headers=xff) as c:
        token = None
        while time.time() < stop_at:
            try:
                if token is None:
                    r = await c.post("/auth/token", json={"username": user, "password": pwd})
                    token = r.json().get("access_token") if r.status_code == 200 else None
                if token:
                    amount = round(random.uniform(1, 200), 2)
                    src, dst = random.choice([("ACC-BOT-1", "ACC-BOT-2"), ("ACC-BOT-2", "ACC-BOT-1")])
                    await c.post("/api/payments", headers={"Authorization": f"Bearer {token}"},
                                 json={"from": src, "to": dst, "amount": amount})
                    if random.random() < 0.4:
                        await c.get("/api/fees/quote", params={"amount": amount})
                    if random.random() < 0.3:
                        await c.get("/api/payments?limit=10", headers={"Authorization": f"Bearer {token}"})
            except httpx.HTTPError:
                token = None
            bursting = time.time() < burst_until[0]
            await asyncio.sleep(random.expovariate(1 / (0.35 if bursting else 1.1)))


async def burst_scheduler(stop_at: float, burst_until: list):
    while time.time() < stop_at:
        # ne jamais dormir au-delà de l'heure de fin : sinon le script ne s'arrête que 1 à 4 minutes en retard
        await asyncio.sleep(min(random.uniform(60, 240), max(0.0, stop_at - time.time())))
        if time.time() >= stop_at:
            break
        burst_until[0] = time.time() + random.uniform(20, 40)


async def main_async(a):
    stop_at = time.time() + a.minutes * 60
    burst_until = [0.0]
    ips = a.source_ips.split(",")[:a.sources] if a.source_ips else [None] * a.sources
    spoofs = a.spoof_ips.split(",")[:a.sources] if a.spoof_ips else [None] * a.sources
    spoofs += [None] * (len(ips) - len(spoofs))  # --spoof-ips plus court que --sources : les suivantes sans identité simulée
    tasks = [burst_scheduler(stop_at, burst_until)]
    for ip, spoof_ip in zip(ips, spoofs):
        tasks += [client_loop(a.base, ip, stop_at, burst_until, a.user, a.password, spoof_ip)
                  for _ in range(a.clients_per_source)]
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1")
    ap.add_argument("--minutes", type=float, default=120)
    ap.add_argument("--sources", type=int, default=5)
    ap.add_argument("--source-ips", help="IP locales sources, séparées par des virgules (ex. 192.168.137.31,...)")
    ap.add_argument("--spoof-ips", help="identités simulées (X-Forwarded-For), une par source, séparées par des "
                                         "virgules ; pour un essai sur un seul poste. Sans effet si TRUSTED_PROXIES "
                                         "n'est pas réglé côté WAF")
    ap.add_argument("--clients-per-source", type=int, default=2)
    ap.add_argument("--user", default="demo-bot")   # compte machine : les humains exigent le visage
    ap.add_argument("--password", default="demo-password")
    a = ap.parse_args()
    if a.spoof_ips:
        import ipaddress
        import sys
        for v in a.spoof_ips.split(",")[:a.sources]:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                sys.exit(f"REFUS : --spoof-ips contient une adresse invalide : '{v}'")
    asyncio.run(main_async(a))
