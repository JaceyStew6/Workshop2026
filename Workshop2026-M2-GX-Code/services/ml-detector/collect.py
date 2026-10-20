"""Exporte les features réelles depuis Prometheus vers un CSV (pour train.py / evaluate.py).

  python collect.py --prom http://localhost:9090 --minutes 120 --out data/normal.csv
  python collect.py ... --label-from 2026-10-21T10:30:00Z --label-to 2026-10-21T10:32:00Z \
                        --out data/labeled.csv     # marque la fenêtre d'attaque (label=1)

Procédure recommandée : lancer redteam/normal_traffic.py pendant >= 2 h (rafales légitimes
comprises), puis exporter. Ne JAMAIS laisser une attaque dans le CSV d'entraînement.
"""
import argparse
import time
from datetime import datetime

import pandas as pd
import requests

from features import FEATURES, PROMQL


def ts(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prom", default="http://localhost:9090")
    ap.add_argument("--minutes", type=float, default=120)
    ap.add_argument("--end", help="ISO8601, défaut = maintenant")
    ap.add_argument("--step", type=int, default=5)
    ap.add_argument("--out", required=True)
    ap.add_argument("--label-from")
    ap.add_argument("--label-to")
    a = ap.parse_args()

    end = ts(a.end) if a.end else time.time()
    start = end - a.minutes * 60
    cols = {}
    for name in FEATURES:
        r = requests.get(f"{a.prom}/api/v1/query_range", timeout=60, params={
            "query": PROMQL[name], "start": start, "end": end, "step": a.step})
        r.raise_for_status()
        res = r.json()["data"]["result"]
        cols[name] = pd.Series({float(t): float(v) for t, v in res[0]["values"]}) if res else pd.Series(dtype=float)

    df = pd.DataFrame(cols).sort_index()
    missing = df.isna().mean().round(3).to_dict()
    df = df.dropna()
    df["label"] = 0
    if a.label_from and a.label_to:
        df.loc[(df.index >= ts(a.label_from)) & (df.index <= ts(a.label_to)), "label"] = 1
    df.reset_index(drop=True).to_csv(a.out, index=False)
    print(f"{len(df)} lignes -> {a.out} | part de valeurs manquantes par feature: {missing}")


if __name__ == "__main__":
    main()
