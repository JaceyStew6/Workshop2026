"""Répétition de la démonstration : une attaque, une sonde « client légitime », un verdict mesuré.

  python tools/rehearsal.py --rps 300 --duration 120 --spoof-ip 198.51.100.61 --out tests/rehearsals/run-1

Ce que fait le script, SANS aucune intervention pendant l'attaque :
  1. lance redteam/attack_flood.py (durée fixe, bien plus longue que le temps de reprise attendu) ;
  2. pendant ce temps, joue un client légitime (devis + virement toutes les secondes) ;
  3. lit l'incident côté moteur de remédiation (GET /v1/state) ;
  4. écrit un JSON de mesures et un verdict.

Critères de réussite (tous obligatoires) :
  * l'incident passe à RECOVERED (pas CONTAINED / ESCALATED) ;
  * l'IP bannie est bien celle de l'attaquant (jamais la passerelle ni l'hôte) ;
  * la reprise a lieu PENDANT que l'attaque continue (preuve que c'est la remédiation qui agit, pas la fin du script) ;
  * après la reprise, ≥ 95 % des virements du client légitime aboutissent (HTTP 201) alors que l'attaque se poursuit ;
  * pendant l'incident, la dégradation est réellement observable (au moins un échec ou une latence > 500 ms).

Sur un seul poste, --spoof-ip simule l'identité de l'attaquant (voir README « Essai sur un seul poste »). Sur le
vrai dispositif à deux PC, lancer l'attaque depuis le PC Attaquant et utiliser --no-attack ici : le script ne
joue alors que le client légitime et la lecture de l'incident.
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def call(base, method, path, body=None, headers=None, timeout=10):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"content-type": "application/json", **(headers or {})})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = json.loads(r.read() or b"{}")
            return r.status, round((time.perf_counter() - t0) * 1000), payload
    except urllib.error.HTTPError as e:
        return e.code, round((time.perf_counter() - t0) * 1000), {}
    except Exception:
        return 0, round((time.perf_counter() - t0) * 1000), {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1", help="WAF (chemin public)")
    ap.add_argument("--state", default="http://127.0.0.1:8088", help="tableau de bord (relaye GET /v1/state du moteur)")
    ap.add_argument("--rps", type=int, default=300)
    ap.add_argument("--duration", type=int, default=120)
    ap.add_argument("--spoof-ip", help="identité simulée de l'attaquant (un seul poste)")
    ap.add_argument("--no-attack", action="store_true", help="ne pas lancer l'attaque (lancée depuis le PC Attaquant)")
    ap.add_argument("--password-file", default=str(ROOT / ".secrets" / "bot_password"))
    ap.add_argument("--user", default="demo-bot")
    ap.add_argument("--out", required=True, help="dossier de sortie")
    a = ap.parse_args()

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    password = Path(a.password_file).read_text().strip()
    status, _, tok = call(a.base, "POST", "/auth/token", {"username": a.user, "password": password})
    if status != 200:
        sys.exit(f"connexion impossible (HTTP {status}) : plateforme arrêtée ou mot de passe incorrect")
    auth = {"authorization": "Bearer " + tok["access_token"]}

    before = call(a.state, "GET", "/v1/state")[2]
    known = {i.get("incident_id") for i in [before.get("last_incident")] if i}

    attack = None
    t_attack = time.time()
    if not a.no_attack:
        cmd = [sys.executable, str(ROOT / "redteam" / "attack_flood.py"), "--target", a.base, "--rps", str(a.rps),
               "--duration", str(a.duration), "--i-own-this-lab", "--allow-loopback"]
        if a.spoof_ip:
            cmd += ["--spoof-ip", a.spoof_ip]
        attack = subprocess.Popen(cmd, stdout=(out / "attack.log").open("w", encoding="utf-8"), stderr=subprocess.STDOUT)
        t_attack = time.time()
    t_end = t_attack + a.duration

    samples = []
    print(f"attaque lancée ({a.rps} req/s, {a.duration} s) ; sonde client légitime en cours, ne touchez à rien...", flush=True)
    while time.time() < t_end + 20:
        t = time.time()
        sq, mq, _ = call(a.base, "GET", "/api/fees/quote?amount=50")
        sp, mp, body = call(a.base, "POST", "/api/payments",
                            {"from": "ACC-BOT-1", "to": "ACC-BOT-2", "amount": "5.00", "idempotency_key": f"reh-{t}"}, auth)
        samples.append({"t": round(t - t_attack, 1), "devis": sq, "devis_ms": mq, "virement": sp, "virement_ms": mp})
        time.sleep(max(0.0, 1.0 - (time.time() - t)))
    if attack:
        attack.wait(timeout=60)

    state = call(a.state, "GET", "/v1/state")[2]
    inc = state.get("last_incident") or {}
    if inc.get("incident_id") in known:
        inc = {}
    banned = [s.get("ip") for s in inc.get("steps", []) if s.get("action") == "BAN_IP" and s.get("ok")]
    t_detect = (inc["received_at"] - t_attack) if inc else None
    t_done = (inc["finished_at"] - t_attack) if inc and inc.get("finished_at") else None

    during = [s for s in samples if t_detect is not None and 0 <= s["t"] <= (t_done or t_detect)]
    degraded = [s for s in samples if (s["devis"] != 200 or s["virement"] != 201 or s["devis_ms"] > 500 or s["virement_ms"] > 500)
                and (t_detect is None or s["t"] <= (t_done or t_detect) + 2)]
    after = [s for s in samples if t_done is not None and s["t"] >= t_done + 2 and s["t"] <= a.duration]
    pay_ok = (sum(1 for s in after if s["virement"] == 201) / len(after)) if after else 0.0
    quote_ok = (sum(1 for s in after if s["devis"] == 200) / len(after)) if after else 0.0

    checks = {
        "incident_recovered": inc.get("state") == "RECOVERED",
        "attacker_banned_not_host": bool(banned) and (a.spoof_ip is None or banned == [a.spoof_ip]),
        "recovery_during_attack": t_done is not None and (a.no_attack or t_done < a.duration - 5),
        "payments_ok_after_recovery_95pct": pay_ok >= 0.95 and len(after) >= 10,
        "degradation_observed": len(degraded) >= 1,
    }
    result = {
        "params": {"rps": a.rps, "duration_s": a.duration, "spoof_ip": a.spoof_ip},
        "incident": {"id": inc.get("incident_id"), "state": inc.get("state"), "class": inc.get("suspected_class"),
                     "score": inc.get("anomaly_score"), "banned": banned,
                     "detected_after_s": round(t_detect, 1) if t_detect is not None else None,
                     "recovered_after_s": round(t_done, 1) if t_done is not None else None,
                     "detect_to_recovered_s": round(t_done - t_detect, 1) if t_done and t_detect is not None else None},
        "client_view": {"samples": len(samples), "degraded_samples": len(degraded),
                        "worst_quote_ms": max((s["devis_ms"] for s in samples), default=None),
                        "worst_payment_ms": max((s["virement_ms"] for s in samples), default=None),
                        "after_recovery_samples": len(after), "payment_success_rate_after": round(pay_ok, 3),
                        "quote_success_rate_after": round(quote_ok, 3)},
        "checks": checks, "verdict": "REUSSI" if all(checks.values()) else "ECHEC",
        "samples": samples,
    }
    (out / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "incident.json").write_text(json.dumps(inc, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "samples"}, indent=2, ensure_ascii=False))
    sys.exit(0 if result["verdict"] == "REUSSI" else 1)


if __name__ == "__main__":
    main()
