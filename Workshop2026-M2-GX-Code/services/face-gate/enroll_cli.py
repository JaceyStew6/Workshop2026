"""Inscription d'un visage DEPUIS L'HÔTE (accès à Docker requis), sans passer par le back-office.

  docker compose exec face-gate python enroll_cli.py <compte> [--label "visage principal"] [--delay 3]

Sert à deux choses que le back-office ne peut pas faire :
  * le PREMIER visage d'un compte humain : tout humain doit passer par la caméra, donc personne ne peut se connecter au
    back-office tant qu'aucun visage n'est inscrit (admin compris) ;
  * la récupération : visage devenu méconnaissable, administrateur verrouillé.
Contrôle d'accès : qui peut lancer `docker compose exec` sur le PC Hôte (déjà administrateur de la plateforme). L'action est
tracée dans le journal d'audit (acteur « host-cli »). L'agent caméra doit tourner (host-agent/run-agent.ps1).
"""
import argparse
import sys
import time

import app as wiring  # câblage de face-gate (base, agent caméra) : mêmes secrets et mêmes réglages que le service


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("username")
    ap.add_argument("--label", default="visage principal")
    ap.add_argument("--delay", type=int, default=3, help="secondes avant d'allumer la caméra (pour se placer)")
    a = ap.parse_args()

    gate = wiring._gate
    gate._spawn = lambda fn: fn()                      # exécution synchrone : on attend la fin de l'inscription
    info = gate.store.user_info(a.username)
    if not info or not info["active"]:
        sys.exit(f"compte inconnu ou désactivé : {a.username}")
    print(f"Inscription du visage de « {a.username} ». Placez UNE seule personne face à la caméra, immobile, bien éclairée.")
    for n in range(a.delay, 0, -1):
        print(f"  caméra dans {n} s...", flush=True)
        time.sleep(1)
    print("  caméra allumée, ne bougez pas...", flush=True)
    job = gate.start_enroll(a.username, a.label, "host-cli", "host")
    st = gate.enroll_status(job["job_id"])
    why = {"no_face": "aucun visage détecté", "multiple_faces": "plusieurs visages dans le champ", "too_small": "visage trop petit : rapprochez-vous",
           "inconsistent": "images incohérentes (une seule personne, sans bouger)", "partial": "trop peu d'images exploitables",
           "timeout": "délai dépassé", "agent_unavailable": "agent caméra injoignable (lancez host-agent/run-agent.ps1)"}
    if st["state"] == "done":
        print(f"OK : visage inscrit pour {a.username} ({st['captured']} images). Caméra éteinte.")
        return
    sys.exit(f"ÉCHEC : {why.get(st['reason'], st['reason'])}")


if __name__ == "__main__":
    main()
