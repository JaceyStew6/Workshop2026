import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pandas as pd
import pytest

from evaluate import evaluate
from features import FEATURES
from gate import Debouncer, IncidentGate
from model import SCORE_AT_THRESHOLD, classify, train
from simulate import simulate_normal, simulate_with_attacks


def test_debouncer_ignores_isolated_spike():
    d = Debouncer(3, 4)
    assert [d.update(x) for x in [False, True, False, False, False]] == [False] * 5


def test_debouncer_fires_on_sustained_anomaly():
    d = Debouncer(3, 4)
    assert [d.update(x) for x in [True, True, True]] == [False, False, True]


def test_gate_fires_once_per_episode_and_rearms():
    g = IncidentGate(rearm_after=3)
    assert g.should_fire(True, True) is True
    assert g.should_fire(True, True) is False          # même épisode : pas de doublon
    for _ in range(3):
        g.should_fire(False, False)                    # retour au calme
    assert g.should_fire(True, True) is True           # nouvel épisode


def test_gate_rearms_after_max_hold_if_never_calm():
    g = IncidentGate(rearm_after=99, max_hold=5)
    g.should_fire(True, True)
    for _ in range(5):
        g.should_fire(True, True)
    assert g.open is False


@pytest.fixture(scope="module")
def bundle():
    df = simulate_normal(120, 42)[FEATURES]
    cut = int(len(df) * 0.7)
    return train(df.iloc[:cut], df.iloc[cut:])


def test_normal_scores_below_threshold_mostly(bundle):
    s = bundle.score(simulate_normal(60, 3)[FEATURES])
    assert (s >= SCORE_AT_THRESHOLD).mean() < 0.02


def test_flood_scores_above_threshold(bundle):
    row = pd.DataFrame([{"req_rate": 400, "max_ip_req_rate": 380, "latency_p95_ms": 1800,
                         "ratio_5xx": 0.4, "ratio_4xx": 0.02, "cpu_pct": 95,
                         "mem_mb": 160, "active_conns": 220}])
    assert bundle.score(row)[0] >= SCORE_AT_THRESHOLD


def test_classification_availability_vs_compromise(bundle):
    flood = {"req_rate": 400, "max_ip_req_rate": 380, "latency_p95_ms": 1800, "ratio_5xx": 0.4,
             "ratio_4xx": 0.02, "cpu_pct": 95, "mem_mb": 160, "active_conns": 220}
    scan = {"req_rate": 20, "max_ip_req_rate": 6, "latency_p95_ms": 50, "ratio_5xx": 0.0,
            "ratio_4xx": 0.7, "cpu_pct": 20, "mem_mb": 150, "active_conns": 18}
    assert classify(bundle, flood) == "availability"
    assert classify(bundle, scan) == "compromise"


def test_end_to_end_detects_all_simulated_floods(bundle):
    df, _ = simulate_with_attacks(60, 11, n_attacks=8)
    r = evaluate(bundle, df)
    assert r["detected"] == r["attacks"]
    assert r["delay_s_max"] <= 30
