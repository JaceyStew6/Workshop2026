"""Test de bout en bout du parcours biométrique, À TRAVERS LE WAF, avec la caméra SIMULÉE de l'agent hôte.

Prérequis : pile démarrée, agent lancé en mode simulé  (.\\host-agent\\run-agent.ps1 -Fake)
            et compte « admin » encore sans exigence faciale (premier démarrage).
  python tests/e2e/face_flow.py --base http://127.0.0.1

Il crée un utilisateur jetable (e2e-face-<horodatage>), inscrit un visage simulé, déroule les cas de la consigne avec les
VRAIS délais (≈ 2 minutes), enregistre la séquence du voyant telle que la verrait l'ESP8266, puis désactive l'utilisateur.
Un échec d'assertion arrête le test avec le détail.
"""
import argparse
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]


def secret(name):
    return (ROOT / ".secrets" / name).read_text().strip()


class Led:
    """Imite la boucle du firmware : interroge /gate/device/led et note chaque changement de motif."""
    def __init__(self, c, base):
        self.c, self.base, self.log = c, base, []

    def poll(self):
        r = self.c.get(self.base + "/gate/device/led", headers={"x-device-token": secret("device_token")})
        r.raise_for_status()
        j = r.json()
        if not self.log or self.log[-1][1] != j["pattern"]:
            self.log.append((round(time.time() - T0, 1), j["pattern"]))
        return j


def check(cond, msg):
    print(("  ok   " if cond else "  ECHEC ") + msg)
    if not cond:
        sys.exit(1)


def main():
    global T0
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1")
    ap.add_argument("--agent", default="http://127.0.0.1:8095")
    a = ap.parse_args()
    T0 = time.time()
    c = httpx.Client(timeout=10)
    agent = httpx.Client(base_url=a.agent, headers={"Authorization": "Bearer " + secret("face_agent_token")}, timeout=10)
    led = Led(c, a.base)

    def person(name):
        agent.post("/v1/fake/person", json={"name": name}).raise_for_status()

    def camera_on():
        return agent.get("/v1/health").json()["camera_on"]

    def wait_state(sid, wanted, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            st = c.get(f"{a.base}/gate/session/{sid}").json()
            led.poll()
            if st["state"] in wanted:
                return st
            time.sleep(0.5)
        raise SystemExit(f"état {wanted} non atteint : {st}")

    print("1. Compte exempté (demo-user) : mot de passe seul, comme avant")
    r = c.post(a.base + "/auth/token", json={"username": "demo-user", "password": secret("demo_password")})
    check(r.status_code == 200 and "payments:create" in r.json()["perms"], "demo-user connecté, habilitations payments:*")
    check(c.post(a.base + "/gate/identify", json={"username": "demo-user"}).json() == {"face_required": False},
          "aucune caméra pour demo-user")
    check(not camera_on(), "caméra éteinte")

    print("2. Administration (admin sans exigence faciale au premier démarrage)")
    r = c.post(a.base + "/auth/token", json={"username": "admin", "password": secret("admin_password")})
    if r.status_code != 200:
        sys.exit("admin exige déjà le visage (ou mot de passe changé) : ce test vise l'état initial. " + r.text)
    admin = {"authorization": "Bearer " + r.json()["access_token"]}
    check("backoffice:users" in r.json()["perms"], "admin porte les habilitations du back-office")
    op = c.post(a.base + "/auth/token", json={"username": "operator", "password": secret("operator_password")}).json()
    check(c.get(a.base + "/auth/admin/users", headers={"authorization": "Bearer " + op["access_token"]}).status_code == 403,
          "operator ne peut PAS gérer les utilisateurs (habilitation refusée)")
    check(c.post(a.base + "/api/payments", headers=admin, json={"from": "ACC-DEMO-1", "to": "ACC-DEMO-2", "amount": "1.00"}).status_code == 403,
          "admin ne peut pas émettre de virement (pas payments:create)")

    user = f"e2e-face-{int(time.time())}"
    pw = "Mot-de-passe-e2e-1234"
    r = c.post(a.base + "/auth/admin/users", headers=admin, json={"username": user, "password": pw, "role": "operator"})
    check(r.status_code == 201, f"utilisateur jetable {user} créé")
    r = c.patch(f"{a.base}/auth/admin/users/{user}", headers=admin, json={"face_required": True})
    check(r.status_code == 409, "exiger le visage sans empreinte est refusé (évite de verrouiller le compte)")

    print("3. Inscription du visage simulé « alice-e2e »")
    person("alice-e2e")
    job = c.post(a.base + "/gate/faces/enroll", headers=admin, json={"username": user, "label": "e2e"}).json()
    for _ in range(40):
        st = c.get(f"{a.base}/gate/faces/enroll/{job['job_id']}", headers=admin).json()
        if st["state"] != "running":
            break
        time.sleep(0.5)
    check(st["state"] == "done", f"inscription terminée ({st})")
    users = {u["username"]: u for u in c.get(a.base + "/auth/admin/users", headers=admin).json()}
    check(users[user]["face_required"] and users[user]["faces"] == 1, "l'exigence faciale s'est activée à la 1re inscription")
    check(not camera_on(), "caméra éteinte après l'inscription")
    r = c.post(a.base + "/auth/token", json={"username": user, "password": pw})
    check(r.status_code == 403, "mot de passe correct SEUL : refusé par auth-service (ticket facial requis)")

    print("4. Visage inconnu -> LED rouge fixe 30 s, caméra OFF ensuite")
    person("intrus")
    sid = c.post(a.base + "/gate/identify", json={"username": user}).json()["session_id"]
    st = wait_state(sid, {"denied"})
    check(st["led"]["pattern"] == "red_solid" and st["attempts_left"] == 1 and camera_on(), "refusé, LED rouge fixe, 1 nouvel essai, caméra encore allumée")
    check(c.post(a.base + "/gate/identify", json={"username": user}).status_code == 423, "pas de 2e identification pendant la temporisation")
    st = wait_state(sid, {"closed"}, timeout=40)
    check(not camera_on() and led.poll()["pattern"] == "off", "après 30 s : caméra éteinte, LED éteinte, identifiant ressaisissable")

    print("5. Bon visage + mauvais mot de passe -> LED rouge clignotante 10 s, caméra OFF")
    person("alice-e2e")
    sid = c.post(a.base + "/gate/identify", json={"username": user}).json()["session_id"]
    st = wait_state(sid, {"awaiting_password"})
    check(st["led"]["pattern"] == "green_blink", "reconnu : LED verte clignotante")
    time.sleep(2)
    check(led.poll()["pattern"] == "green_blink", "elle continue de clignoter tant que le mot de passe n'est pas saisi")
    r = c.post(a.base + "/gate/password", json={"session_id": sid, "password": "mauvais-mot-de-passe"})
    check(r.status_code == 401 and r.json()["restart"], "mot de passe faux : identification à recommencer")
    check(led.poll()["pattern"] == "red_blink" and not camera_on(), "LED rouge clignotante, caméra éteinte")
    st = wait_state(sid, {"closed"}, timeout=20)
    check(led.poll()["pattern"] == "off", "après 10 s : LED éteinte")

    print("6. Bon visage + bon mot de passe -> LED verte fixe 30 s, jeton remis")
    sid = c.post(a.base + "/gate/identify", json={"username": user}).json()["session_id"]
    wait_state(sid, {"awaiting_password"})
    r = c.post(a.base + "/gate/password", json={"session_id": sid, "password": pw})
    check(r.status_code == 200 and "access_token" in r.json(), "connexion réussie")
    check(led.poll()["pattern"] == "green_solid" and not camera_on(), "LED verte fixe, caméra éteinte")
    me = c.get(a.base + "/auth/me", headers={"authorization": "Bearer " + r.json()["access_token"]})
    check(me.status_code == 200 and me.json()["role"] == "operator", "le jeton est valide (/auth/me)")
    check(c.get(a.base + "/auth/admin/audit", headers={"authorization": "Bearer " + r.json()["access_token"]}).status_code == 200,
          "operator lit l'audit (backoffice:audit) mais pas les utilisateurs")
    t_ok = time.time()
    while led.poll()["pattern"] == "green_solid" and time.time() - t_ok < 40:
        time.sleep(0.5)
    held = time.time() - t_ok
    check(28 <= held <= 32 and led.poll()["pattern"] == "off", f"voyant vert fixe pendant {held:.1f} s (30 s attendues), puis éteint")

    print("7. Deux échecs consécutifs -> blocage 5 min")
    person("intrus")
    for i in range(2):
        sid = c.post(a.base + "/gate/identify", json={"username": user}).json()["session_id"]
        wait_state(sid, {"denied"})
        wait_state(sid, {"closed"}, timeout=40)
    r = c.post(a.base + "/gate/identify", json={"username": user})
    check(r.status_code == 429 and r.json()["blocked_s"] > 200, "identification bloquée ~5 min (même avec le bon visage)")
    person("alice-e2e")
    check(c.post(a.base + "/gate/identify", json={"username": user}).status_code == 429, "le bon visage n'y change rien")

    print("8. Nettoyage")
    c.patch(f"{a.base}/auth/admin/users/{user}", headers=admin, json={"face_required": False, "active": False})
    for f in c.get(a.base + "/gate/faces", headers=admin, params={"username": user}).json():
        c.delete(f"{a.base}/gate/faces/{f['id']}", headers=admin)
    person("nobody")
    check(not camera_on(), "caméra éteinte en fin de test")

    print("\nSéquence du voyant observée par l'ESP (t en s):")
    for t, p in led.log:
        print(f"  {t:6.1f}  {p}")
    print("\nTOUS LES CONTRÔLES SONT PASSÉS")


if __name__ == "__main__":
    main()
