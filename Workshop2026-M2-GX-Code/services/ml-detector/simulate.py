"""Simulateur de métriques : SERT À DÉVELOPPER ET TESTER LE PIPELINE AVANT D'AVOIR LA STACK.

Les chiffres qu'il produit ne mesurent PAS la performance réelle du détecteur. Dès que la
plateforme tourne, on remplace ces données par celles de collect.py (trafic réel) et on
refait train.py / evaluate.py. Les paramètres ci-dessous sont des hypothèses de laboratoire.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from features import FEATURES

STEP_S = 5  # une ligne toutes les 5 s


def _base(n: int, rng: np.random.Generator, burst_prob: float) -> pd.DataFrame:
    t = np.arange(n)
    load = 20 * (1 + 0.25 * np.sin(2 * np.pi * t / 240))            # oscillation lente
    req = load * rng.lognormal(0, 0.15, n)
    sources = 5                                                      # générateur de charge multi-IP
    share = rng.uniform(1 / sources, 2.2 / sources, n)
    lat = 45 * rng.lognormal(0, 0.18, n)
    cpu = 8 + req * 0.6 + rng.normal(0, 2, n)
    mem = 150 + rng.normal(0, 4, n)
    conns = 8 + req * 0.5 + rng.normal(0, 2, n)
    r5 = np.clip(rng.normal(0.001, 0.001, n), 0, None)
    r4 = np.clip(rng.normal(0.02, 0.008, n), 0, None)

    # rafales LÉGITIMES : débit x2-3 sur 20-40 s, latence quasi stable (source classique de faux positifs)
    i = 0
    while i < n:
        if rng.random() < burst_prob:
            length = int(rng.integers(4, 9))
            k = slice(i, min(n, i + length))
            m = rng.uniform(2, 3)
            req[k] *= m
            cpu[k] *= 1 + 0.4 * (m - 1)
            conns[k] *= 1 + 0.5 * (m - 1)
            lat[k] *= rng.uniform(1.0, 1.4)
            i += length
        i += 1

    df = pd.DataFrame({
        "req_rate": req, "max_ip_req_rate": req * share, "latency_p95_ms": lat,
        "ratio_5xx": r5, "ratio_4xx": r4, "cpu_pct": np.clip(cpu, 1, None),
        "mem_mb": mem, "active_conns": np.clip(conns, 1, None),
    })
    df["label"] = 0
    return df


def simulate_normal(minutes: float, seed: int, burst_prob: float = 0.03) -> pd.DataFrame:
    n = int(minutes * 60 / STEP_S)
    return _base(n, np.random.default_rng(seed), burst_prob)


def inject_flood(df: pd.DataFrame, start: int, length: int, rps: float,
                 rng: np.random.Generator) -> pd.DataFrame:
    """Flood HTTP depuis UNE IP : montée en ~15-25 s, saturation de l'API, erreurs 5xx."""
    df = df.copy()
    ramp = int(rng.integers(3, 6))
    for j in range(length):
        i = start + j
        if i >= len(df):
            break
        f = min(1.0, (j + 1) / ramp)
        atk = rps * f * rng.lognormal(0, 0.1)
        saturation = min(1.0, atk / 400)
        df.loc[i, "req_rate"] += atk
        df.loc[i, "max_ip_req_rate"] = atk
        df.loc[i, "latency_p95_ms"] = df.loc[i, "latency_p95_ms"] * (1 + 40 * saturation * f) + rng.normal(0, 20)
        df.loc[i, "ratio_5xx"] = min(0.9, 0.55 * saturation * f + rng.uniform(0, 0.03))
        df.loc[i, "cpu_pct"] = min(100, df.loc[i, "cpu_pct"] + 85 * saturation * f)
        df.loc[i, "active_conns"] += 220 * saturation * f
        df.loc[i, "label"] = 1
    return df


def simulate_with_attacks(minutes: float, seed: int, n_attacks: int, rps_range=(120, 600)):
    rng = np.random.default_rng(seed)
    df = simulate_normal(minutes, seed + 1)
    n = len(df)
    slot = n // n_attacks
    starts = []
    for a in range(n_attacks):
        length = int(rng.integers(14, 22))                        # ~70-110 s
        start = a * slot + int(rng.integers(slot // 3, slot // 2))
        df = inject_flood(df, start, length, float(rng.uniform(*rps_range)), rng)
        starts.append(start)
    return df[FEATURES + ["label"]], starts
