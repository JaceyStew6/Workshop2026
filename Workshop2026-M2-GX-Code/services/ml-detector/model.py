"""Modèle de détection d'anomalies : Isolation Forest sur features log-transformées.

Pourquoi Isolation Forest : non supervisé (on n'a que du trafic normal, l'attaque n'est
jamais dans l'entraînement), rapide, peu gourmand, et explicable (écart aux percentiles normaux).

Score normalisé : score = min(1, 0.7 * brut / seuil_brut). Le seuil brut est le quantile
`QUANTILE` des scores bruts d'un jeu de VALIDATION normal distinct de l'entraînement, donc
`score >= 0.70` signifie « plus anormal que 99,9 % du trafic normal observé ».
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from features import FEATURES, LOG_FEATURES

QUANTILE = 0.999  # 0.995 donnait des faux incidents quand la validation est courte (< 2 h) :
                  # le quantile reposait sur 1-2 échantillons. Voir README, section « Faux positifs ».
SCORE_AT_THRESHOLD = 0.70


def _prep(df: pd.DataFrame) -> np.ndarray:
    x = df[FEATURES].astype(float).copy()
    for col in LOG_FEATURES:
        x[col] = np.log1p(x[col].clip(lower=0))
    return x.to_numpy()


@dataclass
class Bundle:
    scaler: StandardScaler
    forest: IsolationForest
    threshold_raw: float
    p99: Dict[str, float] = field(default_factory=dict)  # percentile 99 normal, par feature
    version: str = "1.0"
    n_train: int = 0

    def raw(self, df: pd.DataFrame) -> np.ndarray:
        return -self.forest.score_samples(self.scaler.transform(_prep(df)))

    def score(self, df: pd.DataFrame) -> np.ndarray:
        return np.minimum(1.0, SCORE_AT_THRESHOLD * self.raw(df) / self.threshold_raw)

    def deviating_features(self, row: Dict[str, float]) -> List[str]:
        """Features au-dessus du p99 normal : sert à classer et à justifier l'alerte."""
        return [f for f in FEATURES if row.get(f) is not None and row[f] > self.p99[f]]


def train(train_df: pd.DataFrame, valid_df: pd.DataFrame, seed: int = 42) -> Bundle:
    scaler = StandardScaler().fit(_prep(train_df))
    forest = IsolationForest(n_estimators=300, contamination="auto", random_state=seed)
    forest.fit(scaler.transform(_prep(train_df)))
    bundle = Bundle(scaler=scaler, forest=forest, threshold_raw=1.0, n_train=len(train_df))
    bundle.threshold_raw = float(np.quantile(bundle.raw(valid_df), QUANTILE))
    both = pd.concat([train_df, valid_df])
    bundle.p99 = {f: float(np.quantile(both[f].astype(float), 0.99)) for f in FEATURES}
    return bundle


def classify(bundle: Bundle, row: Dict[str, float]) -> str:
    """Heuristique documentée (le ML détecte, il ne qualifie pas).

    availability : débit, saturation ou latence anormaux -> réponse = bloquer la source + reprise
    compromise   : ratio 4xx anormal avec débit normal (scan, brute force, injection)
                   -> réponse = isoler + alerter, PAS de simple redémarrage
    unknown      : anomalie sans signature claire -> escalade humaine
    """
    dev = set(bundle.deviating_features(row))
    if dev & {"req_rate", "max_ip_req_rate", "latency_p95_ms", "ratio_5xx", "active_conns", "cpu_pct"}:
        return "availability"
    if "ratio_4xx" in dev:
        return "compromise"
    return "unknown"
