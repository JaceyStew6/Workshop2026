#!/usr/bin/env python3
"""Scénario de bout en bout NATIF : trafic normal -> flood -> détection -> reprise -> nouvelle transaction.

Aucune intervention humaine entre le lancement de l'attaque et la fin : ce script ne fait QU'observer
(lecture de /v1/state) puis exécuter la transaction de contrôle. Il n'appelle jamais l'API d'administration.

  RUN=/tmp/ra-run python3 tests/e2e/e2e_scenario.py --out tests/e2e/results/flood-1
"""
import argparse
import json
import statistics
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN = "/tmp/ra-run"


def get_json(url, timeout=3):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


def med(xs):
    return round(statistics.median(xs), 1) if xs else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--base", default="http://192.168.137.1:18080")
    ap.add_argument("--state", default="http://127.0.0.1:18000/v1/state?history=600")
    ap.add_argument("--baseline", type=int, default=60, help="secondes de trafic normal avant l'attaque")
    ap.add_argument("--rps", type=int, default=300)
    ap.add_argument("--attack-seconds", type=int, default=75)
    ap.add_argument("--attacker-ip", default="192.168.137.20")
    ap.add_argument("--max-wait", type=int, default=240)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    pwd = Path(RUN, ".secrets/demo_password").read_text().strip()

    print("[1] trafic normal en arrière-plan", flush=True)
    normal = subprocess.Popen(
        [sys.executable, str(ROOT / "redteam/normal_traffic.py"), "--base", a.base, "--minutes", str((a.baseline + a.max_wait) / 60 + 1),
         "--sources", "5", "--clients-per-source", "2", "--source-ips", "192.168.137.31,192.168.137.32,192.168.137.33,192.168.137.34,192.168.137.35",
         "--user", "demo-user", "--password", pwd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(a.baseline)
    before = get_json(a.state)
    if before.get("open_incidents"):
        print("ABANDON : un incident est déjà ouvert avant l'attaque (faux positif sur trafic normal)")
        normal.terminate()
        sys.exit(2)

    print(f"[2] flood {a.rps} rps pendant {a.attack_seconds} s depuis {a.attacker_ip}", flush=True)
    t_attack = time.time()
    atk = subprocess.Popen(
        [sys.executable, str(ROOT / "redteam/attack_flood.py"), "--target", a.base.replace(":18080", ":18080"), "--rps", str(a.rps),
         "--duration", str(a.attack_seconds), "--source-ip", a.attacker_ip, "--i-own-this-lab"],
        stdout=open(out / "attack.log", "w"), stderr=subprocess.STDOUT)

    final = None
    timeline = []
    deadline = t_attack + a.max_wait
    while time.time() < deadline:
        time.sleep(1)
        try:
            st = get_json(a.state)
        except Exception as exc:          # le moteur lui-même est injoignable : on le note, on continue
            timeline.append({"t": round(time.time() - t_attack, 1), "err": type(exc).__name__})
            continue
        inc = (st.get("open_incidents") or [None])[0] or st.get("last_incident")
        timeline.append({"t": round(time.time() - t_attack, 1), "service": (st.get("current") or {}).get("state"),
                         "ms": (st.get("current") or {}).get("ms"), "incident": inc and inc["state"]})
        if inc and inc["state"] in ("RECOVERED", "CONTAINED", "ESCALATED") and inc["received_at"] >= t_attack - 5:
            final = inc
            break
    print("[3] transaction de contrôle PENDANT que l'attaque continue (l'attaquant est banni)", flush=True)
    smoke_during = subprocess.run([sys.executable, str(ROOT / "tools/smoke.py"), "--base", a.base, "--secret-file", f"{RUN}/.secrets/demo_password"],
                                  capture_output=True, text=True)
    (out / "smoke-during-attack.txt").write_text(smoke_during.stdout + smoke_during.stderr)
    try:
        atk.wait(timeout=a.attack_seconds + 15)
    except subprocess.TimeoutExpired:
        atk.terminate()
    time.sleep(3)
    print("[4] transaction de contrôle APRÈS la fin de l'attaque", flush=True)
    smoke = subprocess.run([sys.executable, str(ROOT / "tools/smoke.py"), "--base", a.base, "--secret-file", f"{RUN}/.secrets/demo_password"],
                           capture_output=True, text=True)
    (out / "smoke-after.txt").write_text(smoke.stdout + smoke.stderr)
    normal.terminate()
    state = get_json(a.state)

    samples = state.get("samples", [])
    t_det = final["received_at"] if final else None
    t_end = final.get("finished_at") if final else None
    bad = [s for s in samples if s["state"] != "up" and s["ts"] >= t_attack]
    result = {
        "attack_started_at": t_attack, "attack_rps": a.rps, "attacker_ip": a.attacker_ip,
        "incident": final and {k: final.get(k) for k in ("incident_id", "state", "suspected_class", "anomaly_score", "duration_s", "target_service")},
        "detection_delay_s": round(t_det - t_attack, 1) if t_det else None,
        "mttr_from_detection_s": final.get("duration_s") if final else None,
        "total_from_attack_to_recovered_s": round(t_end - t_attack, 1) if t_end else None,
        "latency_ms_median_before": med([s["ms"] for s in samples if s["ts"] < t_attack and s["state"] == "up"]),
        "latency_ms_max_during": max([s["ms"] for s in samples if t_attack <= s["ts"] < (t_end or t_attack + 999)], default=None),
        "samples_not_up_during": len(bad),
        "latency_ms_median_after": med([s["ms"] for s in samples if t_end and s["ts"] > t_end and s["state"] == "up"]),
        "steps": final and [{"t": round(s["ts"] - t_attack, 1), "action": s["action"], "ip": s.get("ip"), "ok": s["ok"], "detail": s["detail"]} for s in final["steps"]],
        "transitions": final and [{"t": round(t["ts"] - t_attack, 1), "state": t["state"], "why": t["why"]} for t in final["transitions"]],
        "verification": final and final.get("verification"),
        "transaction_during_attack_ok": smoke_during.returncode == 0,
        "post_incident_transaction_ok": smoke.returncode == 0,
    }
    (out / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
    (out / "timeline.json").write_text(json.dumps(timeline))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(0 if (final and final["state"] == "RECOVERED" and smoke.returncode == 0 and smoke_during.returncode == 0) else 1)


if __name__ == "__main__":
    main()
