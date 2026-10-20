"""Boucle de détection live : Prometheus -> score -> anti faux positifs -> POST /v1/incidents.

Principes :
  * métrique manquante => échantillon ignoré (jamais remplacé par 0, ce qui fabriquerait de l'anormal)
  * Prometheus injoignable => compteur d'erreurs exposé, aucune action
  * échec d'envoi à la remédiation => nouvelle tentative au tick suivant (l'incident n'est pas perdu)
  * le score et l'état sont exposés en métriques (/metrics:9101) pour Grafana et le dashboard
"""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone

import joblib
import pandas as pd
import requests
from prometheus_client import Counter, Gauge, start_http_server

from features import FEATURES, fetch_sample, fetch_top_ip
from gate import Debouncer, IncidentGate
from model import SCORE_AT_THRESHOLD, classify

PROM = os.environ.get("PROMETHEUS_URL", "http://prometheus:9090")
REMEDIATION = os.environ.get("REMEDIATION_URL", "http://remediation-engine:8000")
MODEL_PATH = os.environ.get("MODEL_PATH", "/models/iforest.joblib")
THRESHOLD = float(os.environ.get("ANOMALY_THRESHOLD", SCORE_AT_THRESHOLD))
TICK = float(os.environ.get("TICK_SECONDS", "5"))
K, N = int(os.environ.get("DEBOUNCE_K", "3")), int(os.environ.get("DEBOUNCE_N", "4"))


def read_secret(env: str) -> str:
    path = os.environ.get(env)
    return open(path).read().strip() if path else ""


TOKEN = read_secret("REMEDIATION_TOKEN_FILE")

g_score = Gauge("anomaly_score", "Score d'anomalie normalisé (0.70 = seuil)")
g_threshold = Gauge("anomaly_threshold", "Seuil de déclenchement")
g_open = Gauge("incident_open", "1 si un incident est ouvert côté détecteur")
c_incidents = Counter("incidents_sent_total", "Incidents envoyés à la remédiation")
c_send_err = Counter("incident_send_errors_total", "Échecs d'envoi à la remédiation")
c_prom_err = Counter("prometheus_errors_total", "Erreurs de lecture Prometheus")
c_missing = Counter("samples_missing_features_total", "Échantillons ignorés (métrique absente)")

log = logging.getLogger("ml-detector")


def build_incident(bundle, row: dict, score: float) -> dict:
    now = datetime.now(timezone.utc)
    try:
        top = fetch_top_ip(PROM)
    except Exception:  # l'incident part quand même, sans l'IP
        top = None
    return {
        "incident_id": f"inc-{now:%Y%m%d-%H%M%S}",
        "detected_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "source": "ml-detector",
        "model": {"name": "isolation_forest", "version": bundle.version},
        "anomaly_score": round(float(score), 3),
        "threshold": THRESHOLD,
        "target_service": "payment-api",
        "evidence": {
            "req_rate_per_ip": top or {},
            "latency_p95_ms": round(row["latency_p95_ms"], 1),
            "error_rate_5xx": round(row["ratio_5xx"], 3),
            "deviating_features": bundle.deviating_features(row),
        },
        "suspected_class": classify(bundle, row),
    }


def send(incident: dict) -> bool:
    try:
        r = requests.post(f"{REMEDIATION}/v1/incidents", json=incident,
                          headers={"X-Service-Token": TOKEN}, timeout=3)
        r.raise_for_status()
        return True
    except Exception as exc:
        c_send_err.inc()
        log.error("envoi incident impossible: %s", exc)
        return False


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    bundle = joblib.load(MODEL_PATH)
    start_http_server(9101)
    g_threshold.set(THRESHOLD)
    deb, gate = Debouncer(K, N), IncidentGate()
    pending = None
    log.info("détecteur prêt (modèle %s, seuil %.2f, déclenchement %d/%d)", bundle.version, THRESHOLD, K, N)

    while True:
        t0 = time.time()
        try:
            row = fetch_sample(PROM)
        except Exception as exc:
            c_prom_err.inc()
            log.warning("Prometheus: %s", exc)
            time.sleep(TICK)
            continue

        if any(row[f] is None for f in FEATURES):
            c_missing.inc()
        else:
            score = float(bundle.score(pd.DataFrame([row]))[0])
            g_score.set(score)
            above = score >= THRESHOLD
            if gate.should_fire(deb.update(above), above):
                pending = build_incident(bundle, row, score)
                log.warning("ANOMALIE score=%.2f classe=%s", score, pending["suspected_class"])
                c_incidents.inc()
            g_open.set(1 if gate.open else 0)

        if pending and send(pending):
            pending = None
        time.sleep(max(0.0, TICK - (time.time() - t0)))


if __name__ == "__main__":
    main()
