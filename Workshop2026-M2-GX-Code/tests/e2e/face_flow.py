"""Test de bout en bout du parcours biométrique, À TRAVERS LE WAF, avec la caméra SIMULÉE de l'agent hôte.

Prérequis : pile démarrée ; agent lancé en mode simulé (arrêter l'agent réel d'abord) :  .\\host-agent\\run-agent.ps1 -Fake
  python tests/e2e/face_flow.py --base http://127.0.0.1

Il ne touche ni aux comptes réels ni à leurs visages : il crée deux comptes jetables (e2e-admin-<horodatage>, e2e-face-<horodatage>),
inscrit pour l'utilisateur des visages SIMULÉS, déroule les cas de la consigne avec les VRAIS délais (≈ 2,5 minutes), enregistre la séquence
du voyant telle que la verrait l'ESP8266, puis désactive les comptes et supprime leurs empreintes.
Règle vérifiée : tout UTILISATEUR du portail passe par le visage (aucune connexion par mot de passe seul) ; seuls les comptes machine et
les comptes d'administration (back-office) se connectent avec un mot de passe seul.
"""
import argparse
import hashlib
import secrets as pysecrets
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
T0 = time.time()


def secret(name):
    return (ROOT / ".secrets" / name).read_text().strip()


def sh(*args, **kw):
    return subprocess.run(["docker", "compose", *args], cwd=ROOT, capture_output=True, text=True, timeout=120, **kw)


def sql(q):
    r = sh("exec", "-T", "postgres", "psql", "-U", "postgres_admin", "-d", "payments", "-v", "ON_ERROR_STOP=1", "-c", q)
    if r.returncode:
        sys.exit("SQL en échec : " + r.stderr)


def scrypt_hash(pw):
    salt = pysecrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt${2 ** 14}${salt.hex()}${dk.hex()}"


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
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1")
    ap.add_argument("--agent", default="http://127.0.0.1:8095")
    a = ap.parse_args()
    c = httpx.Client(timeout=10)
    agent = httpx.Client(base_url=a.agent, headers={"Authorization": "Bearer " + secret("face_agent_token")}, timeout=10)
    led = Led(c, a.base)
    try:
        if agent.get("/v1/health").json()["backend"] != "FakeBackend":
            sys.exit("L'agent n'est pas en mode simulé : arrêtez-le puis lancez .\\host-agent\\run-agent.ps1 -Fake")
    except httpx.HTTPError:
        sys.exit("Agent injoignable : lancez .\\host-agent\\run-agent.ps1 -Fake")

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

    def face_login(user, pw, who):
        """Parcours complet : identifiant, visage (simulé : `who`), mot de passe. Retourne la réponse du mot de passe."""
        person(who)
        sid = c.post(a.base + "/gate/identify", json={"username": user}).json()["session_id"]
        wait_state(sid, {"awaiting_password"})
        return c.post(a.base + "/gate/password", json={"session_id": sid, "password": pw})

    ts = int(time.time())
    admin_user, user = f"e2e-admin-{ts}", f"e2e-face-{ts}"
    admin_pw, pw = "Mot-de-passe-admin-e2e-1", "Mot-de-passe-e2e-1234"

    print("1. Règle : le portail exige le visage ; administration et comptes machine se connectent par mot de passe seul")
    r = c.post(a.base + "/auth/token", json={"username": "demo-user", "password": secret("demo_password")})
    check(r.status_code == 403 and "access_token" not in r.text, "demo-user (portail) + bon mot de passe SEUL : refusé (HTTP 403)")
    r = c.post(a.base + "/auth/token", json={"username": "demo-bot", "password": secret("bot_password")})
    check(r.status_code == 200 and "payments:create" in r.json()["perms"], "demo-bot (compte machine) : mot de passe seul accepté")
    check(c.post(a.base + "/gate/identify", json={"username": "demo-bot"}).json() == {"face_required": False}, "aucune caméra pour un compte machine")
    r = c.post(a.base + "/auth/token", json={"username": "admin", "password": secret("admin_password")})
    check(r.status_code == 200 and "backoffice:users" in r.json()["perms"], "admin (administration) : identifiant + mot de passe, sans visage")
    check(c.post(a.base + "/gate/identify", json={"username": "admin"}).json() == {"face_required": False}, "aucune caméra pour l'administration")
    check(not camera_on(), "caméra éteinte")

    print("2. Administration : compte jetable, utilisateur du portail jetable")
    sql(f"INSERT INTO users (username, password_hash, role) VALUES ('{admin_user}', '{scrypt_hash(admin_pw)}', 'admin')")
    r = c.post(a.base + "/auth/token", json={"username": admin_user, "password": admin_pw})
    check(r.status_code == 200 and "backoffice:users" in r.json()["perms"], "administrateur jetable connecté par mot de passe seul")
    admin = {"authorization": "Bearer " + r.json()["access_token"]}
    check(c.post(a.base + "/api/payments", headers=admin, json={"from": "ACC-DEMO-1", "to": "ACC-DEMO-2", "amount": "1.00"}).status_code == 403,
          "l'administrateur ne peut pas émettre de virement (pas payments:create)")
    r = c.patch(f"{a.base}/auth/admin/users/demo-user", headers=admin, json={"face_required": False})
    check(r.status_code == 422, "désactiver l'exigence faciale d'un utilisateur du portail est refusé par l'API")
    r = c.post(a.base + "/auth/admin/users", headers=admin, json={"username": f"x{ts}", "password": pw, "role": "automation"})
    check(r.status_code == 422, "on ne peut pas donner le rôle machine à un utilisateur pour contourner le visage")
    r = c.post(a.base + "/auth/admin/users", headers=admin, json={"username": user, "password": pw, "role": "user"})
    check(r.status_code == 201, f"utilisateur du portail jetable {user} créé")
    r = c.post(a.base + "/auth/token", json={"username": user, "password": pw})
    check(r.status_code == 403, "il ne peut pas se connecter tant que son visage n'est pas inscrit")
    person("alice-e2e")
    r = sh("exec", "-T", "face-gate", "python", "enroll_cli.py", user, "--delay", "0")
    check(r.returncode == 0 and "visage inscrit" in r.stdout, "premier visage inscrit depuis l'hôte (enroll_cli.py)")
    check(not camera_on(), "caméra éteinte après l'inscription")

    print("3. Inscription d'un second visage simulé « alice-e2e » depuis le back-office")
    person("alice-e2e")
    job = c.post(a.base + "/gate/faces/enroll", headers=admin, json={"username": user, "label": "e2e"}).json()
    for _ in range(40):
        st = c.get(f"{a.base}/gate/faces/enroll/{job['job_id']}", headers=admin).json()
        if st["state"] != "running":
            break
        time.sleep(0.5)
    check(st["state"] == "done", f"inscription terminée ({st})")
    users = {u["username"]: u for u in c.get(a.base + "/auth/admin/users", headers=admin).json()}
    check(users[user]["face_required"] and users[user]["faces"] == 2 and not users[admin_user]["face_required"],
          "visage obligatoire pour l'utilisateur (2 empreintes), pas pour l'administration")
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
    wait_state(sid, {"closed"}, timeout=20)
    check(led.poll()["pattern"] == "off", "après 10 s : LED éteinte")

    print("6. Bon visage + bon mot de passe -> LED verte fixe 30 s, jeton remis")
    r = face_login(user, pw, "alice-e2e")
    check(r.status_code == 200 and "access_token" in r.json(), "connexion réussie")
    tok = {"authorization": "Bearer " + r.json()["access_token"]}
    check(led.poll()["pattern"] == "green_solid" and not camera_on(), "LED verte fixe, caméra éteinte")
    me = c.get(a.base + "/auth/me", headers=tok).json()
    check(me["role"] == "user" and "payments:create" in me["perms"], "le jeton est valide (/auth/me) : rôle user, habilitations payments:*")
    check(c.get(a.base + "/auth/admin/users", headers=tok).status_code == 403 and c.get(a.base + "/auth/admin/audit", headers=tok).status_code == 403,
          "un utilisateur du portail n'a aucun accès à l'administration")
    t_ok = time.time()
    while led.poll()["pattern"] == "green_solid" and time.time() - t_ok < 40:
        time.sleep(0.5)
    held = time.time() - t_ok
    check(28 <= held <= 32 and led.poll()["pattern"] == "off", f"voyant vert fixe pendant {held:.1f} s (30 s attendues), puis éteint")

    print("7. Deux échecs consécutifs -> blocage 5 min")
    person("intrus")
    for _ in range(2):
        sid = c.post(a.base + "/gate/identify", json={"username": user}).json()["session_id"]
        wait_state(sid, {"denied"})
        wait_state(sid, {"closed"}, timeout=40)
    r = c.post(a.base + "/gate/identify", json={"username": user})
    check(r.status_code == 429 and r.json()["blocked_s"] > 200, "identification bloquée ~5 min (même avec le bon visage)")
    person("alice-e2e")
    check(c.post(a.base + "/gate/identify", json={"username": user}).status_code == 429, "le bon visage n'y change rien")

    print("8. Nettoyage (comptes et empreintes jetables)")
    sql(f"DELETE FROM face_templates WHERE username IN ('{user}', '{admin_user}'); "
        f"UPDATE users SET active=false WHERE username IN ('{user}', '{admin_user}')")
    person("nobody")
    check(not camera_on(), "caméra éteinte en fin de test")

    print("\nSéquence du voyant observée par l'ESP (t en s):")
    for t, p in led.log:
        print(f"  {t:6.1f}  {p}")
    print("\nTOUS LES CONTRÔLES SONT PASSÉS")


if __name__ == "__main__":
    main()
