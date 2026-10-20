"""Évaluation de bout en bout, avec la MÊME logique de déclenchement que le détecteur live.

  python evaluate.py --model ../../models/iforest.joblib
  python evaluate.py --model ... --csv data/labeled.csv     # trafic réel étiqueté (colonne label)

Métriques qui comptent pour la démo (pas l'accuracy) :
  - attaques détectées / total, et délai de détection (s) depuis le début de l'attaque
  - faux incidents par heure sur trafic normal (rafales légitimes comprises)
"""
import argparse
import json

import joblib
import numpy as np
import pandas as pd

from features import FEATURES
from gate import Debouncer, IncidentGate
from model import SCORE_AT_THRESHOLD
from simulate import STEP_S, simulate_normal, simulate_with_attacks


def run_stream(bundle, df: pd.DataFrame, k=3, n=4):
    scores = bundle.score(df[FEATURES])
    deb, gate = Debouncer(k, n), IncidentGate()
    fired = []
    for i, s in enumerate(scores):
        above = s >= SCORE_AT_THRESHOLD
        if gate.should_fire(deb.update(above), above):
            fired.append(i)
    return scores, fired


def attack_episodes(label: np.ndarray):
    eps, i = [], 0
    while i < len(label):
        if label[i]:
            j = i
            while j < len(label) and label[j]:
                j += 1
            eps.append((i, j))
            i = j
        else:
            i += 1
    return eps


def evaluate(bundle, df, k=3, n=4):
    _, fired = run_stream(bundle, df, k, n)
    eps = attack_episodes(df["label"].to_numpy())
    delays, missed = [], 0
    matched = set()
    for (a, b) in eps:
        hit = [f for f in fired if a <= f < b + 6]
        if hit:
            delays.append((hit[0] - a) * STEP_S)
            matched.add(hit[0])
        else:
            missed += 1
    false_inc = [f for f in fired if f not in matched]
    hours = len(df) * STEP_S / 3600
    return {
        "attacks": len(eps), "detected": len(eps) - missed,
        "delay_s_median": float(np.median(delays)) if delays else None,
        "delay_s_max": float(max(delays)) if delays else None,
        "false_incidents": len(false_inc),
        "false_incidents_per_hour": round(len(false_inc) / hours, 2) if hours else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="../../models/iforest.joblib")
    ap.add_argument("--csv")
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    bundle = joblib.load(a.model)

    out = {}
    if a.csv:
        out["real_labeled"] = evaluate(bundle, pd.read_csv(a.csv))
    else:
        out["SIMULATION_normal_only_3h"] = evaluate(
            bundle, simulate_normal(180, a.seed).assign(label=0))
        df, _ = simulate_with_attacks(120, a.seed + 1, n_attacks=20)
        out["SIMULATION_20_floods_mixed_intensity"] = evaluate(bundle, df)
        weak, _ = simulate_with_attacks(60, a.seed + 2, n_attacks=10, rps_range=(60, 120))
        out["SIMULATION_10_weak_floods_60-120rps"] = evaluate(bundle, weak)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
