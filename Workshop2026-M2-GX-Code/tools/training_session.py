"""Session de collecte pour l'entraînement du détecteur : alterne des phases ACTIVES et des phases d'INACTIVITÉ.

  python tools/training_session.py --base http://127.0.0.1 --hours 2.2 --password-file .secrets/bot_password

Pourquoi : un modèle entraîné sur un trafic continu apprend que « rien ne se passe » est anormal (faux
incidents au repos), et un enregistrement court rend le seuil instable (quantile 99,9 % calculé sur trop peu
d'échantillons). Cette session produit plusieurs heures de trafic varié :
  * phases actives de durée et d'intensité variables (1 à 3 clients par source), avec les rafales légitimes
    déjà générées par redteam/normal_traffic.py ;
  * phases d'inactivité réelles entre deux phases actives, et une inactivité finale.

À FAIRE pendant la session : ne rien lancer d'autre sur la plateforme (ni attaque, ni test), garder le PC
éveillé, et ARRÊTER le détecteur (`docker compose stop ml-detector`) : une fausse alerte pendant la collecte
bannirait le générateur de trafic lui-même et contaminerait les données (vu en pratique).

Le journal des phases (horodatage UTC de chaque début/fin) est écrit en JSON lignes dans --log. Ensuite :
  cd services/ml-detector
  python collect.py --prom http://127.0.0.1:9090 --end <fin de session> --minutes <durée totale + 2> --out data/normal.csv
  python train.py --csv data/normal.csv --out ../../models/iforest.joblib
"""
import argparse
import json
import random
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1")
    ap.add_argument("--hours", type=float, default=2.2, help="durée totale de la session")
    ap.add_argument("--active-min", type=float, nargs=2, default=[8, 14], metavar=("MIN", "MAX"),
                    help="durée d'une phase active, en minutes (tirée au hasard dans l'intervalle)")
    ap.add_argument("--idle-min", type=float, nargs=2, default=[3, 7], metavar=("MIN", "MAX"),
                    help="durée d'une phase d'inactivité, en minutes")
    ap.add_argument("--final-idle-min", type=float, default=5, help="inactivité finale, en minutes")
    ap.add_argument("--password-file", default=str(ROOT / ".secrets" / "bot_password"))
    ap.add_argument("--user", default="demo-bot")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--log", default=str(ROOT / "services" / "ml-detector" / "data" / "training_session.jsonl"))
    a = ap.parse_args()

    password = Path(a.password_file).read_text().strip()
    rng = random.Random(a.seed)
    Path(a.log).parent.mkdir(parents=True, exist_ok=True)
    start = time.time()
    deadline = start + a.hours * 3600 - a.final_idle_min * 60

    def log(**event):
        event["ts"] = now()
        with open(a.log, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        print(json.dumps(event, ensure_ascii=False), flush=True)

    log(phase="session_start", hours=a.hours, seed=a.seed)
    n = 0
    while time.time() < deadline:
        n += 1
        remaining_min = (deadline - time.time()) / 60
        active = min(rng.uniform(*a.active_min), remaining_min)
        clients = rng.choice([1, 2, 3])
        log(phase="active_start", n=n, minutes=round(active, 1), clients_per_source=clients)
        subprocess.run([sys.executable, str(ROOT / "redteam" / "normal_traffic.py"), "--base", a.base,
                        "--minutes", str(active), "--user", a.user, "--password", password,
                        "--clients-per-source", str(clients)], check=False)
        log(phase="active_end", n=n)
        if time.time() >= deadline:
            break
        idle = min(rng.uniform(*a.idle_min), (deadline - time.time()) / 60)
        log(phase="idle_start", n=n, minutes=round(idle, 1))
        time.sleep(max(0.0, idle * 60))
        log(phase="idle_end", n=n)
    log(phase="final_idle_start", minutes=a.final_idle_min)
    time.sleep(a.final_idle_min * 60)
    log(phase="session_end", total_minutes=round((time.time() - start) / 60, 1))


if __name__ == "__main__":
    main()
