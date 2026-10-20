"""Contrat de métriques et extraction des features.

Ce fichier est le CONTRAT entre l'infra (qui doit exposer ces métriques) et l'IA/Data
(qui les consomme). Si une métrique change de nom, on ne modifie qu'ici.

Métriques attendues dans Prometheus :
  waf_requests_total{client_ip, status}                 compteur, exporté par le WAF
  http_request_duration_seconds_bucket{service, le}     histogramme, exporté par payment-api
  process_cpu_seconds_total{job="payment-api"}          prometheus-client (processus payment-api)
  (cAdvisor ne voit pas les conteneurs individuels sous Docker Desktop/WSL2 : métrique de processus à la place)
  waf_connections_active                                jauge exportée par le WAF

Note : la mémoire du processus (process_resident_memory_bytes) a été retirée des FEATURES. Dans un
processus long-vivant, elle ne varie presque jamais en fonctionnement normal (quasi aucune dispersion) ;
un seul échantillon d'entraînement où elle atteint son maximum observé suffit alors à dominer le score
d'isolation et à faire monter le seuil bien au-dessus de ce qu'une vraie attaque atteint -- vérifié en
pratique : un échantillon strictement normal sur toutes les autres variables a obtenu le raw score le
plus élevé du jeu d'entraînement uniquement à cause d'un pic de mémoire sans rapport avec la charge.
"""
from __future__ import annotations

import math
from typing import Dict, Optional

import requests

FEATURES = [
    "req_rate",         # requêtes/s totales vues par le WAF
    "max_ip_req_rate",  # requêtes/s de l'IP la plus active
    "latency_p95_ms",   # latence p95 de payment-api
    "ratio_5xx",        # part de réponses 5xx
    "ratio_4xx",        # part de réponses 4xx (scans, brute force, injections bloquées)
    "cpu_pct",          # CPU du conteneur payment-api (100 = 1 cœur)
    "active_conns",     # connexions actives au WAF
]

# Features à distribution très asymétrique : on applique log1p avant la mise à l'échelle.
LOG_FEATURES = ["req_rate", "max_ip_req_rate", "latency_p95_ms", "cpu_pct", "active_conns"]

_TOTAL = 'sum(rate(waf_requests_total[15s]))'

PROMQL: Dict[str, str] = {
    "req_rate": _TOTAL,
    "max_ip_req_rate": "max(sum by (client_ip) (rate(waf_requests_total[15s])))",
    # Fenêtre élargie à 60 s (au lieu de 30) : au repos (quelques requêtes seulement dans la fenêtre),
    # histogram_quantile() interpole sur très peu d'échantillons et produit un p95 bruité, parfois
    # bien au-dessus de la latence réelle -- vérifié en pratique. 60 s moyenne sur deux fois plus de
    # requêtes au repos, sans perdre en réactivité pendant une vraie attaque (des centaines de
    # requêtes y arrivent de toute façon en quelques secondes).
    "latency_p95_ms": (
        'histogram_quantile(0.95, sum by (le) '
        '(rate(http_request_duration_seconds_bucket{service="payment-api"}[60s]))) * 1000'
    ),
    # `or vector(0)` : sans aucune erreur, la série n'existe pas. « Pas d'erreur » vaut 0, pas « métrique absente »
    # (sinon le détecteur ignorerait tous ses échantillons en fonctionnement normal et resterait aveugle).
    "ratio_5xx": f'(sum(rate(waf_requests_total{{status=~"5.."}}[15s])) or vector(0)) / clamp_min({_TOTAL}, 0.001)',
    "ratio_4xx": f'(sum(rate(waf_requests_total{{status=~"4.."}}[15s])) or vector(0)) / clamp_min({_TOTAL}, 0.001)',
    "cpu_pct": 'sum(rate(process_cpu_seconds_total{job="payment-api"}[15s])) * 100',
    "active_conns": "sum(waf_connections_active)",
}

TOP_IP_QUERY = "topk(1, sum by (client_ip) (rate(waf_requests_total[15s])))"


def query_scalar(prom_url: str, promql: str, timeout: float = 3.0) -> Optional[float]:
    """Valeur scalaire d'une requête instantanée, ou None si la série est absente/NaN."""
    r = requests.get(f"{prom_url}/api/v1/query", params={"query": promql}, timeout=timeout)
    r.raise_for_status()
    result = r.json()["data"]["result"]
    if not result:
        return None
    value = float(result[0]["value"][1])
    return None if math.isnan(value) else value


def fetch_sample(prom_url: str) -> Dict[str, Optional[float]]:
    """Un échantillon de features. Une valeur manquante reste None (jamais remplacée par 0)."""
    return {name: query_scalar(prom_url, q) for name, q in PROMQL.items()}


def fetch_top_ip(prom_url: str) -> Optional[Dict[str, float]]:
    r = requests.get(f"{prom_url}/api/v1/query", params={"query": TOP_IP_QUERY}, timeout=3.0)
    r.raise_for_status()
    result = r.json()["data"]["result"]
    if not result:
        return None
    return {result[0]["metric"].get("client_ip", "unknown"): round(float(result[0]["value"][1]), 1)}
