"""Entraînement : python train.py --csv data/normal.csv --out ../../models/iforest.joblib

Le CSV doit contenir UNIQUEMENT du trafic normal (colonnes = features.FEATURES).
Découpage par blocs contigus de BLOCK_SIZE échantillons, 7 blocs sur 10 en entraînement et 3 sur 10
en validation, en alternant sur toute la durée (jamais un simple coupage tête/queue) : les échantillons
voisins restent groupés (pas de mélange aléatoire, pas de fuite entre échantillons corrélés), mais les
deux lots voient les mêmes régimes de trafic. Un simple coupage 70/30 chronologique mettait TOUTE la
fin d'un enregistrement (ex. la période d'inactivité ajoutée après le trafic actif, voir README
« Entraîner le détecteur ») dans la seule validation : le modèle n'apprenait alors jamais que le calme
est normal, et un vrai repos se retrouvait aussi anormal qu'une attaque -- vérifié en pratique.
Sans --csv : données simulées (développement uniquement).
"""
import argparse
import json

import joblib
import pandas as pd

from features import FEATURES
from model import train
from simulate import simulate_normal

BLOCK_SIZE = 10     # ~50 s à 5 s/échantillon : assez court pour mélanger les régimes, assez long pour
                    # garder des voisins corrélés ensemble (pas de fuite entre entraînement et validation)
TRAIN_BLOCKS_OF = 10  # motif répété : les 7 premiers blocs sur 10 -> entraînement, les 3 suivants -> validation

# Un CSV "normal" peut contenir un épisode contaminé (ex. le générateur de trafic lui-même banni par
# une fausse alerte pendant la collecte : ses propres requêtes reviennent alors massivement en erreur).
# Ce n'est pas du trafic normal, quelle qu'en soit la cause : on l'exclut avant tout découpage, sinon
# le modèle apprend qu'un taux d'erreur énorme est "normal" -- vérifié en pratique (un épisode de ce
# type a fait entrer 24 lignes à >85 % de 4xx dans un entraînement).
MAX_NORMAL_ERROR_RATIO = 0.30


def drop_contaminated(df: pd.DataFrame) -> pd.DataFrame:
    bad = (df["ratio_4xx"] > MAX_NORMAL_ERROR_RATIO) | (df["ratio_5xx"] > MAX_NORMAL_ERROR_RATIO)
    if bad.any():
        print(f"ATTENTION : {bad.sum()} ligne(s) retirée(s) (taux d'erreur > {MAX_NORMAL_ERROR_RATIO:.0%}, "
              "pas du trafic normal -- probablement un incident pendant la collecte)")
    return df[~bad]


def block_split(df: pd.DataFrame):
    is_valid = [(i // BLOCK_SIZE) % TRAIN_BLOCKS_OF >= 7 for i in range(len(df))]
    mask = pd.Series(is_valid, index=df.index)
    return df[~mask], df[mask]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv")
    ap.add_argument("--out", default="../../models/iforest.joblib")
    ap.add_argument("--minutes", type=float, default=120, help="durée simulée si pas de CSV")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    df = pd.read_csv(a.csv)[FEATURES] if a.csv else simulate_normal(a.minutes, a.seed)[FEATURES]
    df = drop_contaminated(df.dropna()).reset_index(drop=True)
    train_df, valid_df = block_split(df)
    bundle = train(train_df, valid_df, seed=a.seed)
    joblib.dump(bundle, a.out)
    print(json.dumps({
        "samples_train": len(train_df), "samples_valid": len(valid_df),
        "threshold_raw": round(bundle.threshold_raw, 4),
        "source": a.csv or "SIMULATION (dev uniquement)", "out": a.out,
    }, indent=2))


if __name__ == "__main__":
    main()
