# Authentification biométrique du back-office et voyant ESP8266 (Consigne additionnelle 1)

La connexion au back-office passe par **trois étapes** : identifiant, reconnaissance faciale par la caméra USB du PC Hôte,
mot de passe. Un voyant bicolore, piloté par un ESP8266 connecté au WiFi du hotspot, indique l'état à l'utilisateur.

## 1. Parcours et règles (ce que la consigne demande, ce que le code fait)

| Étape | Comportement | Où c'est décidé |
|---|---|---|
| 1. Identifiant | Saisie, bouton « Continuer ». Un compte **d'administration** (`admin`, `operator`) ou **machine** (`synthetic-probe`, `demo-bot`) passe directement au mot de passe, caméra éteinte. **Tout utilisateur du portail, `demo-user` compris, passe par la caméra** | `face-gate` (`identify`) |
| 2. Caméra | Allumée **seulement** à ce moment ; quelques images sont analysées en mémoire, comparées aux empreintes chiffrées de l'utilisateur ; aucune image n'est conservée | agent hôte + `face-gate` |
| 2a. Reconnu | Voyant **vert clignotant jusqu'à la saisie du mot de passe** (délai maximal 120 s, puis tout s'éteint) | `face-gate` |
| 2b. Non reconnu | Identifiant **vidé**, voyant **rouge fixe 30 s**, puis caméra **éteinte** et identifiant ressaisissable. **1 nouvel essai**, puis **blocage 5 minutes**, et ainsi de suite (le blocage se répète) | `face-gate` |
| 3. Mot de passe correct | Voyant **vert fixe 30 s** puis éteint, caméra éteinte, jeton d'accès remis, page de back-office affichée | `face-gate` → `auth-service` |
| 3'. Mot de passe faux | Voyant **rouge clignotant 10 fois** puis éteint, caméra éteinte, identifiant et mot de passe vidés, **identification à recommencer** | `face-gate` |
| Par défaut | Voyant **éteint**, caméra **éteinte** | tous |

Choix d'interprétation (à valider avec les enseignants) :
- Les **échecs de mot de passe** ne comptent pas dans le blocage de 5 minutes (la consigne l'associe à la reconnaissance). Ils sont
  limités par `auth-service` (5 échecs / 5 min par compte) et chaque nouvel essai impose un nouveau scan facial.
- **La reconnaissance faciale est obligatoire pour les utilisateurs du portail de paiement.** Elle ne se désactive pas (ni par l'API ni par un drapeau). Sont dispensés : la page d'administration (`/backoffice.html`, mot de passe seul pour les rôles portant la permission `backoffice:access`) et les comptes machine `probe` et `automation`, que l'API refuse d'attribuer à un utilisateur. Un utilisateur du portail sans visage inscrit ne peut pas se connecter. **Choix assumé : le compte le plus puissant (`admin`) est protégé par le mot de passe seul** (risque R16).
- Après un visage non reconnu, la caméra reste allumée pendant les 30 s du voyant rouge, comme l'écrit la consigne (« rouge fixe 30 s, puis caméra éteinte »).

## 2. Architecture

```
navigateur ──► WAF ──► face-gate ──► agent hôte (PC Hôte, 127.0.0.1:8095) ──► caméra USB
                 │        │   └────► auth-service (mot de passe + ticket facial) ──► PostgreSQL
                 │        └────────► PostgreSQL (empreintes chiffrées, audit)
                 └── ESP8266 ── GET /gate/device/led (1/s, jeton) ◄── voyant bicolore
```

- **Agent hôte** (`host-agent/`) : Docker Desktop (WSL2) ne transmet pas une caméra USB à un conteneur Linux, donc la caméra et
  l'IA tournent sur Windows. OpenCV 5 : détecteur de visage **YuNet**, reconnaissance **SFace** (empreinte de 128 nombres, légère, CPU).
  API liée à `127.0.0.1`, jeton secret, caméra ouverte sur demande, **chien de garde** qui l'éteint seul (5 à 300 s).
- **face-gate** (`services/face-gate/`) : machine à états de la connexion, comparaison des empreintes (similarité cosinus ≥ 0,40 sur au
  moins 3 images sur 5), verrouillage, voyant, inscription des visages. Une seule session à la fois (une seule caméra).
- **auth-service** : refuse de délivrer un jeton à tout utilisateur du portail sans **ticket facial** valide (signé HS256 par face-gate,
  120 s, **usage unique**, lié à l'identifiant). Le navigateur ne voit jamais le ticket : face-gate relaie lui-même le mot de passe.
  Un mot de passe volé ne suffit donc pas, même en appelant `/auth/token` directement (testé : HTTP 403).
- **Habilitations** : table `roles` (permissions), jeton JWT avec `perms`, API d'administration `/auth/admin/*` et `/gate/*`. Rôles d'origine : `admin`, `operator`, `user`, `probe`.

### Permissions

| Permission | Autorise |
|---|---|
| `payments:create` / `payments:read` | Émettre / consulter ses virements (payment-api) |
| `backoffice:access` | Entrer dans le back-office |
| `backoffice:users` | Créer, désactiver, changer le rôle, réinitialiser le mot de passe, exiger le visage |
| `backoffice:roles` | Créer / modifier / supprimer des rôles personnalisés |
| `backoffice:faces` | Inscrire et supprimer des visages |
| `backoffice:device` | Voir et tester le voyant, état de la caméra, arrêt d'urgence |
| `backoffice:audit` | Lire le journal d'audit |

Garde-fous : on ne peut accorder que des permissions qu'on détient (pas d'escalade) ; on ne peut pas réduire ses propres droits ; il reste
toujours un administrateur actif ; les rôles système sont immuables ; chaque action d'administration vérifie en base que le compte est
toujours actif (révocation immédiate, même si un jeton de 15 min circule encore) ; tout est tracé dans `audit_log`.

## 3. Voyant ESP8266

| Motif | Quand | Durée |
|---|---|---|
| éteint | repos, caméra éteinte, après toute séquence | — |
| vert clignotant (1 Hz) | visage reconnu, en attente du mot de passe | jusqu'au mot de passe (max 120 s) |
| vert fixe | connexion réussie | 30 s |
| rouge clignotant (1 Hz) | mot de passe faux | 10 s = 10 clignotements |
| rouge fixe | visage non reconnu | 30 s |

Protocole : l'ESP interroge `GET /gate/device/led` chaque seconde (en-tête `X-Device-Token`) et reçoit `{"seq","pattern","remaining_ms"}`.
Il reproduit le clignotement localement et **s'éteint seul** : à l'échéance, ou si le serveur ne répond plus pendant 5 s (échec sûr : jamais
de vert « périmé »). Le même vocabulaire pilote le **voyant virtuel** de l'interface web. Les interrogations réussies ne sont pas comptées dans
les métriques de trafic du WAF (`waf_device_polls_total` à part) afin de ne pas fausser le détecteur ML (mesuré : score au repos inchangé).

Matériel : NodeMCU ESP8266, LED bicolore 3 broches à cathode commune, 2 résistances 220 Ω : GPIO5 (D1) → anode verte, GPIO4 (D2) → anode rouge, cathode → GND.
Code : `firmware/esp8266-led/` (projet **PlatformIO**, à ouvrir dans **CLion** avec le plugin PlatformIO). La logique d'allumage
(`include/led_logic.h`) est indépendante d'Arduino et testée sur PC (`test/run-tests.sh`).

## 4. Mise en route

Première fois (les secrets, la migration de base et l'activation se font avec le reste, voir le README) :

```powershell
# 1. secrets manquants (SOPS : sh tools/init_secrets.sh puis sh tools/render_secrets.sh ; sans SOPS :)
.\.venv\Scripts\python.exe tools\secrets_catalog.py ensure
# 2. agent hôte : dépendances et modèles (une fois)
.\.venv\Scripts\python.exe -m pip install -r host-agent\requirements.txt
.\.venv\Scripts\python.exe host-agent\fetch_models.py
# 3. régler la caméra (la personne se place devant ; aucune image n'est enregistrée)
cd host-agent; ..\.venv\Scripts\python.exe selftest.py --seconds 6; cd ..
# 4. agent hôte (laisser ce terminal ouvert)
.\host-agent\run-agent.ps1
# 5. pile Docker (base déjà existante : sh tools/migrate_db.sh avant, voir README)
docker compose up -d --build --wait
```

Administration : `admin` et `operator` se connectent sur `http://127.0.0.1/backoffice.html` avec leur mot de passe (`.secrets\admin_password`), sans caméra. Utilisateurs
du portail : créer le client (onglet Utilisateurs, rôle `user`), puis inscrire son visage (onglet Visages, la personne devant la caméra) ; ou, pour le premier visage d'un compte,
depuis le PC Hôte : `docker compose exec face-gate python enroll_cli.py demo-user`. Ensuite il se connecte au portail par visage puis mot de passe. Les scripts de test utilisent
le compte machine `demo-bot` (`.secrets\bot_password`, comptes `ACC-BOT-1/2`) : ils ne passent pas par la caméra, et aucun humain ne doit l'utiliser.

Voyant physique : `python tools\make_firmware_config.py --ssid <hotspot>` (génère `include/secrets.h`, non versionné), ouvrir le dossier dans CLion
(ou `pio run -t upload`). Pour que l'ESP joigne le PC il faut que le WAF écoute sur l'IP du hotspot : `HOST_IP=192.168.137.1` dans `.env`
(et autoriser le port 80 dans le pare-feu Windows). Sans ESP : `python firmware\esp8266-led\sim\led_sim.py` affiche le voyant dans le terminal.

## 5. Vie privée et sécurité

- Données biométriques = **données sensibles (RGPD art. 9)**. Ce qu'on garde : une empreinte de 128 nombres par visage inscrit, **chiffrée AES-256-GCM**
  (clé `face_template_key` distincte du mot de passe SQL, identifiant lié au chiffré) ; **jamais d'image**. Suppression possible à tout moment (onglet Visages).
- Caméra : éteinte par défaut, allumée seulement dans une session, extinction forcée par le chien de garde de l'agent même si `face-gate` tombe, bouton d'arrêt d'urgence, alerte `CameraOnTooLong`.
- L'agent n'écoute que `127.0.0.1` (refus de démarrer ailleurs sans `--allow-remote`), exige un jeton, vérifie les modèles par somme de contrôle.
- **Limite connue : pas de détection de vivacité.** Une photo ou une vidéo présentée devant la caméra peut tromper le modèle. Compensations : second facteur (mot de passe), blocage, journal
  d'audit, alerte `FaceAuthFailures`. Une vraie détection de vivacité (caméra infrarouge, défi aléatoire) est la suite logique.
- L'échange avec l'ESP est en HTTP clair sur le WiFi du hotspot (jeton d'appareil exposé en cas d'écoute) : cohérent avec l'écart TLS du prototype (R10). Le jeton ne donne accès qu'à l'état du voyant.
- Taux d'erreur : le seuil (0,40) vient de la recommandation d'OpenCV pour SFace (0,363) avec marge. Fonctionne avec une vraie caméra, mais **les taux de faux rejets et de faux accepts n'ont pas été mesurés** (pas d'échantillon de personnes) : à calibrer si besoin (`FACE_THRESHOLD` dans `.env`).

## 6. Tests

| Test | Commande | Couvre |
|---|---|---|
| Agent hôte (caméra simulée) | `python -m pytest host-agent/tests` | jeton, cycle de vie de la caméra, chien de garde, refus d'images (aucun visage, plusieurs, trop petit) |
| Logique de connexion | `cd services/face-gate; python -m pytest tests` | 29 cas : chaque motif de voyant, blocage répété, caméra jamais allumée sans session, échec fermé, ticket, chiffrement, habilitations |
| auth-service | `cd services/auth-service; python -m pytest tests` | ticket obligatoire pour tout humain (drapeau ignoré), usage unique, signature/expiration/sujet, seuls les comptes machine sans visage, permissions |
| Firmware (logique) | `wsl sh firmware/esp8266-led/test/run-tests.sh` | motifs, 10 clignotements, extinction sûre, débordement de `millis()` |
| Firmware (compilation) | `pio run` | compilé pour NodeMCU v2 : RAM 35 %, flash 28 % |
| Bout en bout à travers le WAF | `python tests/e2e/face_flow.py` | tout le parcours avec les vrais délais et la caméra **simulée** (`run-agent.ps1 -Fake`) |

**Essayé avec une vraie caméra USB** : inscription du visage et connexion en trois étapes fonctionnelles (constat de l'équipe, sans campagne de mesure).

**Non vérifié sur ce poste** : fonctionnement du firmware sur un ESP8266 physique (compilé, logique testée, jamais flashé) ; taux de faux rejets et de faux accepts sur un échantillon de personnes ; résistance à une photo ou une vidéo (aucune détection de vivacité).
