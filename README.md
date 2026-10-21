# PROJECT RESILIENCE-ALPHA : plateforme de paiement (fictive) qui se défend et se répare seule

Workshop 2026 M2, groupe 15<n>. Une plateforme de paiement fictive, attaquée de l'extérieur. Sans
intervention humaine : détection par ML → confinement (bannissement WAF) → redémarrage seulement si
nécessaire → **preuve par une vraie transaction** que le service est rétabli.

Toutes les données sont fictives. Les scripts d'attaque (`redteam/`) refusent toute cible hors réseau
privé et exigent `--i-own-this-lab`.

## État de vérification : à lire avant tout

Le dispositif prévu pour l'évaluation est à deux PC (PC Hôte + PC Attaquant distinct, via le point
d'accès sans fil), avec SOPS/age, Ansible et Ollama. Ce qui a été **réellement vérifié** jusqu'ici, c'est
le déploiement complet **sur un seul poste Windows 11 + Docker Desktop**, par deux chemins : un
démarrage rapide en PowerShell (« Démarrage sur un seul poste ») et le **déploiement officiel
SOPS + age + Ansible sous WSL** (« Déploiement officiel sous WSL »). **Jamais testé** : l'attaque depuis
un second PC, l'IP source réelle vue par le WAF dans ce cas, et l'assistant RAG avec un vrai Ollama.

| Élément | Statut |
|---|---|
| Les 17 services du compose (dont `face-gate`, ajouté pour la consigne additionnelle 1 ; 16 lors des répétitions) | **Construits et démarrés avec succès** sous Docker Desktop (Windows 11) |
| Flux métier complet (connexion, devis, virement, relecture) | **Vérifié** (`tools/smoke.py`) |
| Entraînement du détecteur sur du trafic réel de cette pile | **Vérifié** : 132 min de trafic (9 phases actives d'intensité variable, 9 phases d'inactivité), 1 609 échantillons, 7 mesures. Au repos, le score reste entre 0,40 et 0,58 pour un seuil de 0,70 |
| Chaîne détection → remédiation → reprise (`tools/rehearsal.py`) | **3 répétitions réussies sur 3** (300, 300 puis 500 req/s) : détection en 12 à 17 s, reprise en 21 à 29 s **pendant que l'attaque continue** (preuve que c'est la remédiation qui agit, pas la fin du script), 100 % des virements du client légitime aboutissent ensuite. Détail : `tests/rehearsals/`. L'attaquant est **simulé** sur la même machine |
| Grafana (10 panneaux), Prometheus | **Vérifiés** |
| Loki / Promtail : centralisation des journaux (WAF, moteur, services) | **Vérifié** après correction (le proxy `docker-ro` bloquait `GET /networks`, dont Promtail a besoin : Loki ne recevait rien) |
| SOPS + age : génération et chiffrement des secrets, déchiffrement dans `.secrets/` | **Vérifié** sous WSL Ubuntu 24.04 (voir « Déploiement officiel sous WSL ») |
| Ansible : `deploy.yml`, `backup.yml`, `reset-demo.yml`, `restore.yml` | **Vérifiés** de bout en bout (déploiement 7/7 tâches OK, remise à zéro en 12 s, restauration en 19 s) |
| Tests unitaires (voir « Tests » pour le détail) | **Exécutés** : waf 37/37, remediation-engine 19/19, ml-detector 8/8, rag-assistant 10/10, dashboard 6/6 + build, **face-gate 28/28, auth-service 15/15, agent hôte 12/12** |
| **Consigne additionnelle 1** : back-office en 3 étapes (identifiant, visage, mot de passe), habilitations, voyant ESP8266 (`docs/biometric-auth.md`) | **Vérifié de bout en bout à travers le WAF avec une caméra simulée** (`tests/e2e/face_flow.py`, vrais délais 30 s / 10 s / 5 min), **puis essayé avec une vraie caméra USB : inscription du visage et connexion en trois étapes fonctionnelles** ; interface testée dans un navigateur, firmware **compilé** (PlatformIO, NodeMCU v2) et logique du voyant testée sur PC. **Non vérifié : ESP8266 physique (jamais flashé), taux de faux rejets / faux accepts (non mesurés), détection de vivacité (absente)** |
| Assistant RAG : tests unitaires OK, mais appel réel à Ollama (modèle, embeddings) | **Non vérifié** sur ce poste (pas d'Ollama installé) |
| Scanner de secrets (`tools/check_no_plaintext_secrets.sh`) | **Exécuté** : il confirme que `secrets.enc.yaml` est chiffré ; il signale `.secrets/` présent, ce qui est attendu en local (à rejouer sur l'archive finale) |
| promtool (validation des règles d'alerte) | **Vérifié** (`promtool check rules` : 9 règles, dont 3 pour la biométrie) |
| Dispositif à deux PC, point d'accès sans fil, IP source réelle d'un vrai attaquant | **Non vérifié : à tester en premier sur le vrai dispositif** |

## Architecture en une page

```
PC Attaquant ──► WAF (seul port exposé, :80)
                  ├─ réseau edge : frontend (portail, back-office)
                  ├─ réseau app (interne) : auth-service, payment-api, face-gate, postgres
                  └─ réseau ops (interne) : prometheus, cAdvisor, loki, détecteur ML, moteur de remédiation, proxys Docker
Back-office : identifiant ─► face-gate ─► agent hôte (caméra USB du PC Hôte, reconnaissance faciale) ─► mot de passe ─► auth-service
                                      └──► voyant ESP8266 (WiFi du hotspot), voir docs/biometric-auth.md
Détecteur ML ──► moteur de remédiation ──► WAF admin (bans) + proxy Docker (restart d'UN conteneur autorisé)
                                      └──► sonde : devis → connexion → paiement → relecture → grand livre → 8 s de stabilité
Tableau de bord (React) : état perçu, latence avant/pendant/après, chronologie de l'incident
Assistant opérateur (RAG local, Ollama) : répond depuis docs/, ne peut exécuter aucune action
```
Détails et schémas : `docs/architecture.md`, procédures : `docs/runbooks.md`, risques : `governance/`.

---

## Démarrage sur un seul poste (Windows + Docker Desktop, vérifié)

C'est le chemin à utiliser pour développer, tester et répéter la démo sur un PC de développement
classique, sans deuxième machine ni outillage Linux. Toutes les commandes sont en PowerShell.

### Pré-requis

- Windows 11, Docker Desktop installé et **lancé** (icône baleine dans la barre des tâches).
- Python 3.11+ sur l'hôte (pour les scripts `redteam/` et l'entraînement du détecteur).
- Node.js uniquement si vous voulez lancer les tests du tableau de bord hors Docker (`npm`).

### 1. Première fois : secrets, réseau, environnement Python

```powershell
Set-Location "<chemin du projet>\Workshop2026-M2-GX-Code"

# Secrets en clair, générés localement (sans SOPS/age : voir note plus bas). Ne crée que les secrets MANQUANTS :
# relançable sans rien changer à l'existant (catalogue : tools/secrets_catalog.py).
python tools\secrets_catalog.py ensure

# .env : mode un seul poste (voir section « Essai sur un seul poste » pour TRUSTED_PROXIES)
@'
HOST_IP=127.0.0.1
TRUSTED_PROXIES=172.30.10.0/24
'@ | Set-Content .env

# Environnement Python local (scripts redteam/, entraînement du détecteur)
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -q -r services\ml-detector\requirements.txt

# Agent hôte (caméra USB + reconnaissance faciale du back-office) : dépendances et modèles ONNX (≈ 39 Mo, vérifiés par SHA-256)
.\.venv\Scripts\python.exe -m pip install -q -r host-agent\requirements.txt
.\.venv\Scripts\python.exe host-agent\fetch_models.py
```

> **Mise à jour d'une installation existante** (base déjà créée avant la consigne additionnelle) : appliquer la migration idempotente (habilitations, empreintes, audit), une seule fois, avec `docker compose up -d postgres` démarré :
> `docker compose exec -T postgres sh /docker-entrypoint-initdb.d/30-biometrics.sh` (ou `sh tools/migrate_db.sh`). Une base neuve l'applique d'elle-même. Compléter aussi les secrets : `python tools\secrets_catalog.py ensure` (ou `sh tools/init_secrets.sh` sous SOPS, qui n'ajoute que les manquants).

> **Pourquoi pas SOPS/age/Ansible ?** Le déploiement officiel (section plus bas) les utilise. S'ils ne
> sont pas installés sur votre poste, cette méthode les remplace : secrets en clair dans `.secrets/`
> (déjà ignoré par Git), pas de chiffrement au repos. Suffisant pour un poste de développement, **pas**
> pour un vrai déploiement.
>
> **Si le build échoue avec une erreur de certificat SSL** (`certificate verify failed` : réseau
> d'entreprise, proxy, antivirus qui intercepte TLS) : par défaut la vérification des certificats reste
> **active**. Ajoutez alors ces deux lignes à `.env`, puis relancez `docker compose build` :
> ```
> PIP_EXTRA_ARGS="--trusted-host pypi.org --trusted-host files.pythonhosted.org"
> NPM_STRICT_SSL=false
> ```
> Elles ne désactivent la vérification que **pendant le build des images** (arguments de build des
> `Dockerfile`), jamais à l'exécution. À ne pas utiliser en dehors d'un réseau qui l'impose.

### 2. Construire et démarrer (première fois : sans le détecteur, pas encore de modèle)

```powershell
docker compose build
docker compose up -d --wait --wait-timeout 240 --scale ml-detector=0
.\.venv\Scripts\python.exe tools\smoke.py --base http://127.0.0.1
```

Pour la connexion au back-office, lancer **dans un second terminal laissé ouvert** l'agent de la caméra : `.\host-agent\run-agent.ps1` (ou `-Fake` pour une caméra simulée, sans matériel). Sans lui, `face-gate` répond « service de reconnaissance indisponible » et personne ne se connecte au back-office (échec fermé voulu) ; le portail de paiement n'est pas concerné.

`docker compose ps` doit afficher tous les services `healthy`/`Up`. Le smoke test doit afficher 4
lignes `[OK]`. Accès :

| Service | URL | Identifiants |
|---|---|---|
| Portail de paiement | http://127.0.0.1 | `demo-user` / `Get-Content .secrets\demo_password` |
| **Back-office** (utilisateurs, rôles, visages, voyant, audit) | http://127.0.0.1/backoffice.html | `admin` / `Get-Content .secrets\admin_password` (puis inscrire son visage : il devient exigé) ; `operator` / `.secrets\operator_password` |
| Tableau de bord | http://127.0.0.1:8088 | — |
| Grafana | http://127.0.0.1:3000 | `admin` / `Get-Content .secrets\grafana_password` |
| Prometheus (requêtes brutes uniquement, pas un tableau de bord) | http://127.0.0.1:9090 | — |
| Assistant RAG | http://127.0.0.1:8090 | — |

### 3. Entraîner le détecteur (obligatoire avant de le démarrer)

Voir la section dédiée « Entraîner le détecteur » plus bas pour le détail et les pièges rencontrés.
Résumé rapide :

```powershell
.\.venv\Scripts\python.exe redteam\normal_traffic.py --base http://127.0.0.1 --minutes 15 --password (Get-Content .secrets\demo_password)
# attendre 5 minutes sans toucher au portail (le calme doit aussi être appris comme "normal")
Set-Location services\ml-detector
..\..\.venv\Scripts\python.exe collect.py --prom http://127.0.0.1:9090 --minutes 20 --out data\normal.csv
..\..\.venv\Scripts\python.exe train.py --csv data\normal.csv --out ..\..\models\iforest.joblib
Set-Location ..\..
docker compose up -d --wait --wait-timeout 60 ml-detector
```

### 4. Les fois suivantes (PC déjà configuré, images déjà construites)

Docker Desktop s'arrête à chaque extinction du PC : c'est l'étape la plus souvent oubliée.

```powershell
# 1. Démarrer Docker Desktop (attendre qu'il soit prêt)
Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"

# 2. Agent de la caméra (autre terminal, à laisser ouvert) puis tout relancer (modèle déjà entraîné : le détecteur démarre avec les autres)
Start-Process powershell -ArgumentList '-NoExit','-File','host-agent\run-agent.ps1'
Set-Location "<chemin du projet>\Workshop2026-M2-GX-Code"
docker compose up -d --wait --wait-timeout 240

# 3. Vérifier
.\.venv\Scripts\python.exe tools\smoke.py --base http://127.0.0.1
```

Pour arrêter proprement : `docker compose down` (garde les volumes/données) ou `docker compose down -v`
(efface aussi la base et les bans).

### 5. Back-office biométrique : première mise en route (caméra, premier visage, voyant)

Détail complet : `docs/biometric-auth.md`. Essayé avec une vraie caméra USB : inscription du visage et connexion en trois
étapes fonctionnelles. Dans l'ordre :

```powershell
# a. Régler la caméra : la personne se place devant (aucune image enregistrée, seulement des statistiques).
#    Fermer avant toute application qui utilise la caméra (Teams, Zoom, Appareil photo).
Set-Location host-agent; ..\.venv\Scripts\python.exe selftest.py --seconds 6; Set-Location ..
#    « caméra introuvable » : essayer --camera-index 1 (puis lancer l'agent avec -Camera 1)

# b. Lancer l'agent de la caméra dans un second terminal, à laisser ouvert (à refaire à chaque démarrage du PC)
.\host-agent\run-agent.ps1

# c. Lire le mot de passe du compte admin
Get-Content .secrets\admin_password
```

1. Ouvrir http://127.0.0.1/backoffice.html, saisir `admin`, « Continuer » : tant qu'aucun visage n'est inscrit, le mot de passe est demandé directement.
2. Onglet **Visages** : saisir `admin`, « Inscrire un visage », rester immobile face à la caméra 2 à 5 s, seul dans le champ, bien éclairé.
   L'exigence faciale s'active alors **automatiquement** pour ce compte.
3. Se déconnecter puis se reconnecter : identifiant, visage (voyant vert clignotant), mot de passe (vert fixe 30 s).
   Un visage non reconnu donne un voyant rouge fixe 30 s ; deux échecs de suite bloquent l'identification 5 minutes.
4. Autres comptes : onglet Utilisateurs (créer), puis Visages (inscrire).

Messages d'erreur fréquents : « agent caméra injoignable » = l'agent n'est pas lancé (étape b) ; « service de reconnaissance
indisponible » à la connexion = idem ; faux rejets répétés = réinscrire le visage dans les conditions réelles, ou baisser `FACE_THRESHOLD` dans `.env`
(puis `docker compose up -d face-gate`). Accès de secours si la caméra est perdue : `docs/runbooks.md`, section « Biométrie ».

> Une fois le visage d'`admin` inscrit, `tests/e2e/face_flow.py` ne fonctionne plus tel quel (il suppose `admin` encore sans visage) ;
> les tests unitaires et le reste de la pile ne sont pas concernés.

**Voyant physique (ESP8266, jamais flashé sur ce poste : firmware compilé et logique testée sur PC seulement)** : câblage (LED bicolore, GPIO5 vert,
GPIO4 rouge, 220 Ω) et protocole dans `docs/biometric-auth.md`.

```powershell
# WiFi du hotspot + jeton de l'appareil -> firmware\esp8266-led\include\secrets.h (non versionné ; le mot de passe WiFi est demandé au clavier)
.\.venv\Scripts\python.exe tools\make_firmware_config.py --ssid <nom-du-hotspot>
# Puis ouvrir firmware\esp8266-led dans CLion (plugin PlatformIO) et téléverser (ou : pio run -t upload)
# Sans ESP, voir le voyant dans le terminal :
.\.venv\Scripts\python.exe firmware\esp8266-led\sim\led_sim.py --base http://127.0.0.1
```

Pour que l'ESP joigne le PC, le WAF doit écouter sur l'IP du hotspot : `HOST_IP=192.168.137.1` dans `.env` (puis `docker compose up -d`),
et autoriser le port 80 dans le pare-feu Windows. Sur un réseau d'entreprise qui intercepte TLS, `pio` peut échouer à télécharger sa chaîne d'outils
(`certificate verify failed`) : lui fournir les autorités du magasin Windows plutôt que désactiver la vérification (variables `SSL_CERT_FILE` et `REQUESTS_CA_BUNDLE`
pointant vers un fichier PEM exporté du magasin Windows).

---

## Essai sur un seul poste : bannissement et identités simulées

Sous Docker Desktop, tout le trafic venant de l'hôte (navigateur, scripts, smoke test) arrive au WAF
avec la **même** adresse : la passerelle du réseau `edge` (`172.30.10.1`, sous-réseau fixé dans
`docker-compose.yml`). Un bannissement par IP bloquerait alors l'attaquant **et** les utilisateurs
légitimes en même temps.

`TRUSTED_PROXIES=172.30.10.0/24` dans `.env` (déjà réglé à l'étape 1 ci-dessus) fait en sorte que le
WAF fasse confiance à l'en-tête `X-Forwarded-For` pour simuler des identités distinctes :

```powershell
# Trafic normal avec des identités d'utilisateurs simulées (plage RFC 5737, réservée à la documentation)
.\.venv\Scripts\python.exe redteam\normal_traffic.py --base http://127.0.0.1 --minutes 15 `
  --spoof-ips 203.0.113.11,203.0.113.12,203.0.113.13,203.0.113.14,203.0.113.15 `
  --password (Get-Content .secrets\demo_password)

# Attaque avec une identité distincte -- CHANGER le dernier chiffre à CHAQUE essai, sinon elle retombe
# sur un bannissement déjà actif (10 min de TTL) et rien ne se passe, l'attaque n'atteint jamais le service
.\.venv\Scripts\python.exe redteam\attack_flood.py --target http://127.0.0.1 --rps 250 --duration 150 `
  --allow-loopback --i-own-this-lab --spoof-ip 198.51.100.23
```

Le WAF bannit alors `198.51.100.23`, pas la passerelle : le portail reste joignable pendant l'incident
pour tout le reste du trafic. Pour lever un ban avant son expiration (10 min) :

```powershell
docker compose exec -T remediation-engine python3 -c "import urllib.request; tok=open('/run/secrets/waf_admin_token').read().strip(); req=urllib.request.Request('http://waf:8082/v1/bans/198.51.100.23', method='DELETE', headers={'x-admin-token': tok}); print(urllib.request.urlopen(req, timeout=3).read())"
```

Sans `TRUSTED_PROXIES`, l'en-tête est ignoré (comportement d'origine) : **ne jamais l'activer** sur le
vrai dispositif à deux PC, l'attaquant pourrait sinon falsifier sa propre adresse.

## Rendre la dégradation réellement observable

Par défaut, `payment-api` est volontairement borné (`docker-compose.yml`) pour qu'une attaque sature
réellement le service, au lieu de simplement le ralentir sans jamais le faire échouer :

- `cpus: "0.5"` : un demi-cœur seulement.
- `DB_POOL_MAX: "3"` / `DB_POOL_TIMEOUT: "0.4"` : pool de connexions très étroit, échec net (503) sous
  charge plutôt qu'une file d'attente qui finit toujours par aboutir.

Vérifié : sous une attaque à 250 req/s, le devis **et** le virement échouent franchement (503) pendant
la durée de l'incident, pour tout le monde (pas seulement l'attaquant), jusqu'à ce que le moteur de
remédiation bannisse l'attaquant et que le service redevienne normal — alors même que le script
d'attaque continue de tourner en arrière-plan (preuve que c'est l'IA qui résout l'incident, pas la fin
du chronomètre du script).

## Entraîner le détecteur (obligatoire, et pourquoi c'est plus subtil qu'il n'y paraît)

Le modèle livré dans `models/` est entraîné sur des données SIMULÉES et nommé exprès
`iforest.dev-simulated.joblib` : le compose attend `models/iforest.joblib`, qui n'existe pas tant que
vous ne l'avez pas produit sur VOTRE pile.

```powershell
.\.venv\Scripts\python.exe -m pip install -q -r services\ml-detector\requirements.txt

# 0. Arrêter le détecteur : une fausse alerte pendant la collecte bannirait le générateur de trafic lui-même
docker compose stop ml-detector

# 1. Session de collecte : ~2 h 12 de trafic légitime, phases actives (intensité variable, rafales) alternées
#    avec des phases d'inactivité réelle. Garder le PC éveillé, ne rien lancer d'autre sur la plateforme.
.\.venv\Scripts\python.exe tools\training_session.py --base http://127.0.0.1 --hours 2.2
#    (lit .secrets\demo_password ; journal des phases : services\ml-detector\data\training_session.jsonl)

# 2. Exporter les mesures depuis Prometheus : --end = "session_end" du journal, --minutes = durée totale + 2
Set-Location services\ml-detector
..\..\.venv\Scripts\python.exe collect.py --prom http://127.0.0.1:9090 --end 2026-10-20T16:56:16Z --minutes 134 --out data\normal.csv

# 3. Entraîner
..\..\.venv\Scripts\python.exe train.py --csv data\normal.csv --out ..\..\models\iforest.joblib
Set-Location ..\..

# 4. (Re)démarrer le détecteur avec le nouveau modèle
docker compose up -d --wait --wait-timeout 60 ml-detector
```

Version courte pour un essai rapide (15 min de trafic actif puis 5 min de calme, `redteam\normal_traffic.py
--minutes 15`, ~240 échantillons) : possible, mais le seuil est alors instable (le score oscille autour de 0,70
au repos et un simple bruit déclenche des alertes). La session longue est celle à utiliser avant une
démonstration. Résultat obtenu avec elle : 1 609 échantillons dont 29 % au calme, score au repos entre
0,40 et 0,58, 0,44 % des échantillons normaux au-dessus du seuil, attaque réelle à 0,77.

**Pièges rencontrés et corrigés dans le code** (voir `services/ml-detector/features.py` et `train.py`
pour le détail) :
- La mémoire du processus (`mem_mb`) variait trop peu en fonctionnement normal : un seul relevé à son
  maximum suffisait à fausser tout le calibrage. **Retirée des variables du modèle.**
- Un découpage entraînement/validation en tête/queue mettait toute période de calme dans la seule
  validation : le modèle n'apprenait jamais que le repos est normal. **Remplacé par un découpage en
  blocs alternés** qui couvre les deux régimes.
- `latency_p95_ms` était calculée sur une fenêtre de 30 s, trop bruitée au repos (peu de requêtes).
  **Élargie à 60 s.**
- Si la collecte croise un incident (ex. un faux bannissement pendant la génération de trafic normal),
  `train.py` **rejette désormais automatiquement** les lignes dont le taux d'erreur dépasse 30 % avant
  d'entraîner, pour ne pas apprendre qu'un taux d'erreur massif est "normal".

**Si le score d'anomalie reste élevé même au repos** (visible sur le panneau Grafana « Score d'anomalie
vs seuil », ou `curl http://127.0.0.1:9090/api/v1/query?query=anomaly_score`) : l'hôte a probablement
changé de comportement depuis l'entraînement (redémarrage du PC, autre charge en cours) — réentraînez
avec la procédure ci-dessus.

## Répéter la démonstration (verdict automatique)

```powershell
.\.venv\Scripts\python.exe tools\rehearsal.py --rps 300 --duration 120 --spoof-ip 198.51.100.61 --out tests\rehearsals\run-1
```

Le script lance l'attaque, joue un client légitime (devis + virement chaque seconde), lit l'incident côté moteur
et rend un verdict **REUSSI / ECHEC** selon cinq critères tous obligatoires : incident `RECOVERED`, bannissement
de l'attaquant et non de l'hôte, reprise **pendant** que l'attaque continue, ≥ 95 % de virements réussis après
la reprise, dégradation réellement observée avant. Changer l'identité (`--spoof-ip`) à chaque répétition.
Sur le vrai dispositif à deux PC : lancer l'attaque depuis le PC Attaquant et ajouter `--no-attack` ici.
Résultats des trois répétitions réalisées : `tests/rehearsals/README.md`.

## Déroulé de la démonstration (aucune intervention humaine pendant l'attaque)

1. Ouvrir le tableau de bord (http://127.0.0.1:8088) : état « OPÉRATIONNEL ».
2. Lancer l'attaque (voir « Essai sur un seul poste » pour l'identité simulée si un seul PC).
3. Le tableau de bord passe en dégradé, puis la chronologie affiche : alerte → bannissement →
   vérification → rétabli.
4. Montrer la transaction de contrôle (étapes de vérification) et le journal d'audit.
5. Entre deux essais : lever le ban résiduel si besoin (voir ci-dessus) et relancer avec une nouvelle
   identité simulée.

Tout geste manuel pendant l'attaque fait passer l'axe 1 du barème à ND : s'entraîner à ne rien toucher.

## Tests

Chaque service a ses propres dépendances de test : installez-les dans `.venv` avant de lancer pytest
(le Python système n'a ni `pytest` ni `fastapi`). À faire une fois :

```powershell
.\.venv\Scripts\python.exe -m pip install -q fastapi==0.115.5 "uvicorn[standard]==0.32.1" pydantic==2.10.2 `
  pytest-asyncio==0.24.0 "langchain-core>=0.3,<2" "langchain-text-splitters>=0.3" "langchain-ollama>=0.2"
```

Puis, pour chaque service :

```powershell
Set-Location services\waf;                ..\..\.venv\Scripts\python.exe -m pytest -q tests; Set-Location ..\..
Set-Location services\remediation-engine; ..\..\.venv\Scripts\python.exe -m pytest -q tests; Set-Location ..\..
Set-Location services\ml-detector;        ..\..\.venv\Scripts\python.exe -m pytest -q tests; Set-Location ..\..
Set-Location services\rag-assistant;      ..\..\.venv\Scripts\python.exe -m pytest -q tests; Set-Location ..\..
Set-Location services\dashboard;          npm ci; npm test; npm run build; Set-Location ..\..
Set-Location services\face-gate;         ..\..\.venv\Scripts\python.exe -m pytest -q tests; Set-Location ..\..
Set-Location services\auth-service;      ..\..\.venv\Scripts\python.exe -m pytest -q tests; Set-Location ..\..
Set-Location host-agent;                 ..\.venv\Scripts\python.exe -m pytest -q tests; Set-Location ..
wsl sh firmware/esp8266-led/test/run-tests.sh     # logique du voyant (g++ dans WSL)
# Bout en bout du back-office (pile démarrée + agent en caméra simulée : .\host-agent\run-agent.ps1 -Fake ; ≈ 2 min) :
.\.venv\Scripts\python.exe tests\e2e\face_flow.py --base http://127.0.0.1
```

Pour face-gate et auth-service : `.\.venv\Scripts\python.exe -m pip install -q "pyjwt==2.10.1" "psycopg[binary,pool]==3.2.3" cryptography==43.0.3 httpx==0.27.2` (une fois).

**Résultats vérifiés sur ce poste :**

| Service | Résultat |
|---|---|
| waf | 37 passés |
| remediation-engine | 19 passés |
| ml-detector | 8 passés |
| rag-assistant | 10 passés (un test écrivait son fichier en cp1252 sous Windows ; corrigé en forçant `encoding="utf-8"`) |
| dashboard | 6 passés, `npm run build` réussit |
| face-gate | 28 passés |
| auth-service | 15 passés |
| agent hôte | 12 passés |
| firmware (logique du voyant) | OK ; compilation PlatformIO réussie (RAM 35 %, flash 28 %) |
| `tests/e2e/face_flow.py` | tous les contrôles passés (caméra simulée) |

(`sh tools/check_no_plaintext_secrets.sh` nécessite un shell POSIX — non vérifié sur ce poste.)

## Secrets : consultation rapide

```powershell
Get-Content .secrets\demo_password        # un seul secret
Get-ChildItem .secrets | ForEach-Object { "$($_.Name): $(Get-Content $_.FullName)" }   # tous
```

---

## Déploiement officiel sous WSL (SOPS + age + Ansible) — vérifié sur un seul poste

C'est le dispositif demandé par le sujet : secrets chiffrés (SOPS + age) et opérations automatisées par
Ansible. Les étapes ci-dessous ont été **exécutées** sur ce poste (Windows 11, Docker Desktop, WSL2,
Ubuntu 24.04). Le dispositif à **deux PC** (attaquant distinct, point d'accès sans fil `192.168.137.1`)
reste à valider, voir la fin de cette section. Ollama pour l'assistant RAG : non installé ici.

### Préparer WSL (une seule fois)

```powershell
wsl --install -d Ubuntu-24.04 --no-launch
wsl -d Ubuntu-24.04 -u root -- bash -c "apt-get update -qq && apt-get install -y -qq age ansible curl ca-certificates"
```

`sops` n'est pas dans les dépôts Ubuntu : télécharger le binaire de la dernière version
(https://github.com/getsops/sops/releases, `sops-vX.Y.Z.linux.amd64`) dans `/usr/local/bin/sops`, puis
`chmod +x`. Créer ensuite un utilisateur dédié, le rendre utilisateur par défaut de la distribution et
activer les droits Unix sur le disque Windows (sans cela, `chmod` est refusé sur `/mnt/c` et les
playbooks échouent) :

```powershell
wsl -d Ubuntu-24.04 -u root -- bash -c "useradd -m -s /bin/bash resilience && usermod -aG docker resilience"
wsl -d Ubuntu-24.04 -u root -- bash -c 'printf "[automount]\nenabled = true\noptions = \"metadata,umask=022,fmask=133\"\n\n[user]\ndefault = resilience\n" > /etc/wsl.conf'
```

Activer l'intégration Docker pour la distribution : Docker Desktop → Settings → Resources → WSL
integration → `Ubuntu-24.04`. Puis `wsl --shutdown` et redémarrer Docker Desktop. **Ne pas** faire
`wsl --terminate` pendant que Docker tourne : l'intégration se détache et `docker` n'est alors plus
trouvé dans la distribution (corriger par un redémarrage de Docker Desktop avec la distribution lancée).
Vérifier : `wsl -d Ubuntu-24.04 -- docker version`.

### Déployer

Depuis un terminal Ubuntu (`wsl -d Ubuntu-24.04`), dans le dépôt (ici
`/mnt/c/Users/<vous>/.../Workshop2026-M2-G<n>-Code`) :

```bash
export HOST_IP=127.0.0.1                       # 192.168.137.1 sur le vrai dispositif
sh tools/init_secrets.sh                       # une fois : clé age + secrets chiffrés
                                               # SAUVEGARDEZ ~/.config/sops/age/keys.txt hors dépôt : sans elle,
                                               # secrets.enc.yaml est irrécupérable
cp .env.example .env                           # puis ajuster HOST_IP / TRUSTED_PROXIES (voir .env.example)
ansible-playbook ansible/deploy.yml -e bootstrap=true   # 1er démarrage SANS modèle : tout sauf le détecteur
# ... entraîner le détecteur (section « Entraîner le détecteur ») ...
ansible-playbook ansible/deploy.yml            # démarrage complet, détecteur compris
```

`deploy.yml` déchiffre les secrets (SOPS), construit les images, démarre tous les services (`--wait`)
puis lance le test de fumée. Si les secrets sont régénérés (`FORCE=1 sh tools/init_secrets.sh`), les mots
de passe changent : supprimer d'abord les volumes (`docker compose down -v`), sinon PostgreSQL garde
l'ancien mot de passe.

### Les autres playbooks (tous exécutés)

| Commande | Rôle | Durée mesurée |
|---|---|---|
| `ansible-playbook ansible/backup.yml` | `pg_dump` compressé dans `backups/` | quelques secondes |
| `ansible-playbook ansible/reset-demo.yml` | efface bans et état du détecteur entre deux essais | 12 s |
| `ansible-playbook ansible/restore.yml` | restaure la dernière sauvegarde (`-e backup=backups/<fichier>` pour choisir) | 19 s |

Au quotidien, `docker compose up -d --wait` depuis Windows suffit (voir « Les fois suivantes »).

### Vérifications à faire en premier sur le vrai dispositif (risques connus, non testés ici)

1. **IP source réelle.** Depuis le PC Attaquant, lancer une requête et lire `docker compose logs waf` :
   `client_ip` doit être l'adresse du PC Attaquant, pas une IP interne à Docker. Sinon le bannissement
   par IP ne marche pas : voir `TRUSTED_PROXIES` et l'option d'un proxy natif (risque R7 dans
   `governance/ebios-rm.md`).
2. Tous les conteneurs `healthy` (`docker compose ps`), puis `tools/smoke.py`.
3. `process_cpu_seconds_total{job="payment-api"}` existe dans Prometheus (la sonde du détecteur en
   dépend). cAdvisor ne voit souvent que l'hôte sous Docker Desktop/WSL2 (`id="/"`), jamais les
   conteneurs individuels : `features.py` utilise donc les métriques de processus exposées par
   `payment-api` lui-même, pas cAdvisor.
4. Grafana (http://127.0.0.1:3000) : 10 panneaux, source Loki alimentée.
5. Assistant : poser 5 questions du domaine et 5 hors domaine sur `/ask` et régler `RAG_MIN_SCORE`
   d'après le champ `scores`.

## Arborescence

`services/` (un dossier par composant, dont `face-gate`), `host-agent/` (caméra + reconnaissance faciale sur le PC Hôte), `firmware/esp8266-led/` (voyant, projet PlatformIO/CLion), `infra/` (Prometheus, Loki, Grafana), `ansible/`, `redteam/`
(scénarios d'attaque), `tests/e2e/` (banc d'essai natif et résultats), `tests/rehearsals/` (répétitions sous Docker),
`tools/` (secrets, test de fumée, `training_session.py`, `rehearsal.py`), `docs/`, `governance/` (EBIOS RM, PCA/PRA, NIS2/DORA), `dossier/` (sources du dossier PDF et régénération de la présentation, voir `dossier/README.md`). `.venv/` (environnement Python local,
ignoré par Git) et `services/ml-detector/data/*.csv` (jeux de trafic collectés) apparaissent une fois
le détecteur entraîné sur ce poste.

## Limites assumées

Pas de TLS ; double authentification (visage + mot de passe) seulement pour le back-office, **sans détection de vivacité** ; WAF Python « CRS-lite » (sous-ensemble de règles, pas ModSecurity/Coraza) ; une
seule machine, aucune redondance ; chaîne d'approvisionnement non scannée ; détection 12 à 17 s après le
début d'un flood (fenêtre de 3 échantillons sur 4, un tick de 5 s) ; sur un seul poste, le bannissement par IP ne peut être démontré fidèlement qu'avec
des identités simulées (voir « Essai sur un seul poste »), pas avec de vraies IP distinctes. Liste
complète et chiffrée dans `governance/ebios-rm.md`.
