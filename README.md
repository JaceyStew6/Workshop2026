# PROJECT RESILIENCE-ALPHA : plateforme de paiement (fictive) qui se défend et se répare seule

Workshop 2026 M2, groupe 15<n>. Une plateforme de paiement fictive, attaquée de l'extérieur. Sans
intervention humaine : détection par ML → confinement (bannissement WAF) → redémarrage seulement si
nécessaire → **preuve par une vraie transaction** que le service est rétabli.

Toutes les données sont fictives. Les scripts d'attaque (`redteam/`) refusent toute cible hors réseau
privé et exigent `--i-own-this-lab`.

## État de vérification : à lire avant tout

Le dispositif prévu pour l'évaluation (`DISPOSITIF OFFICIEL` ci-dessous) est à deux PC, avec SOPS/age,
Ansible et Ollama. Il n'a pas encore été vérifié sur ce matériel-là. Ce qui a été **réellement vérifié**
jusqu'ici, c'est le déploiement complet **sur un seul poste Windows 11 + Docker Desktop** (voir
« Démarrage sur un seul poste »), sans WSL, sans Ansible, sans SOPS/age, avec des secrets générés
directement en clair dans `.secrets/` :

| Élément | Statut |
|---|---|
| Les 15 conteneurs du compose (y compris `docker-compose.yml` lui-même) | **Construits et démarrés avec succès** sous Docker Desktop (Windows 11) |
| Flux métier complet (connexion, devis, virement, relecture) | **Vérifié** (`tools/smoke.py`) |
| Entraînement du détecteur sur du trafic réel de cette pile | **Vérifié**, plusieurs itérations (voir « Entraîner le détecteur ») |
| Chaîne détection → remédiation → reprise sur une vraie attaque (`redteam/attack_flood.py`) | **Vérifiée en conditions réelles**, y compris sur une attaque de 150 s où la reprise intervient alors que l'attaque continue (preuve que c'est l'IA qui agit, pas la fin du script) |
| Grafana (10 panneaux), Prometheus, logs WAF/remédiation | **Vérifiés** |
| Tests unitaires (voir « Tests » pour le détail) | **Exécutés** : waf 37/37, remediation-engine 19/19, ml-detector 8/8, rag-assistant 9/10 (1 échec Windows-only, encodage), dashboard 6/6 + build |
| Assistant RAG : tests unitaires OK, mais appel réel à Ollama (modèle, embeddings) | **Non vérifié** sur ce poste (pas d'Ollama installé) |
| SOPS+age, Ansible, scanner de secrets, promtool | **Non vérifiés** sur ce poste (contournés, voir plus bas) |
| Dispositif à deux PC, point d'accès sans fil, IP source réelle d'un vrai attaquant | **Non vérifié : à tester en premier sur le vrai dispositif** |

## Architecture en une page

```
PC Attaquant ──► WAF (seul port exposé, :80)
                  ├─ réseau edge : frontend (portail)
                  ├─ réseau app (interne) : auth-service, payment-api, postgres
                  └─ réseau ops (interne) : prometheus, cAdvisor, loki, détecteur ML, moteur de remédiation, proxys Docker
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

# Secrets en clair, générés localement (sans SOPS/age : voir note plus bas)
New-Item -ItemType Directory -Force .secrets | Out-Null
foreach ($s in "db_password","remediation_token","waf_admin_token","probe_password","demo_password","grafana_password") {
  python -c "import secrets;open('.secrets/$s','w').write(secrets.token_urlsafe(24))"
}
python -c "import secrets;open('.secrets/jwt_secret','w').write(secrets.token_urlsafe(48))"

# .env : mode un seul poste (voir section « Essai sur un seul poste » pour TRUSTED_PROXIES)
@'
HOST_IP=127.0.0.1
TRUSTED_PROXIES=172.30.10.0/24
'@ | Set-Content .env

# Environnement Python local (scripts redteam/, entraînement du détecteur)
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -q -r services\ml-detector\requirements.txt
```

> **Pourquoi pas SOPS/age/Ansible ?** Le déploiement officiel (section plus bas) les utilise. S'ils ne
> sont pas installés sur votre poste, cette méthode les remplace : secrets en clair dans `.secrets/`
> (déjà ignoré par Git), pas de chiffrement au repos. Suffisant pour un poste de développement, **pas**
> pour un vrai déploiement.
>
> **Si le build échoue avec une erreur de certificat SSL** (réseau d'entreprise, proxy, antivirus) :
> les `Dockerfile` de chaque service contiennent déjà un contournement (`pip install --trusted-host`,
> `npm config set strict-ssl false`). Il désactive la vérification des certificats **pendant le
> build uniquement** ; à retirer en dehors de ce type de réseau restreint.

### 2. Construire et démarrer (première fois : sans le détecteur, pas encore de modèle)

```powershell
docker compose build
docker compose up -d --wait --wait-timeout 240 --scale ml-detector=0
.\.venv\Scripts\python.exe tools\smoke.py --base http://127.0.0.1
```

`docker compose ps` doit afficher tous les services `healthy`/`Up`. Le smoke test doit afficher 4
lignes `[OK]`. Accès :

| Service | URL | Identifiants |
|---|---|---|
| Portail de paiement | http://127.0.0.1 | `demo-user` / `Get-Content .secrets\demo_password` |
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

# 2. Tout relancer (modèle déjà entraîné : le détecteur démarre avec les autres)
Set-Location "<chemin du projet>\Workshop2026-M2-GX-Code"
docker compose up -d --wait --wait-timeout 240

# 3. Vérifier
.\.venv\Scripts\python.exe tools\smoke.py --base http://127.0.0.1
```

Pour arrêter proprement : `docker compose down` (garde les volumes/données) ou `docker compose down -v`
(efface aussi la base et les bans).

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

# 1. Trafic légitime, 15 minutes, PUIS 5 minutes sans rien (le calme doit aussi être appris comme "normal")
.\.venv\Scripts\python.exe redteam\normal_traffic.py --base http://127.0.0.1 --minutes 15 --password (Get-Content .secrets\demo_password)
# attendre 5 minutes

# 2. Exporter les features depuis Prometheus (20 min = les 15 min actives + les 5 min de calme)
Set-Location services\ml-detector
..\..\.venv\Scripts\python.exe collect.py --prom http://127.0.0.1:9090 --minutes 20 --out data\normal.csv

# 3. Entraîner
..\..\.venv\Scripts\python.exe train.py --csv data\normal.csv --out ..\..\models\iforest.joblib
Set-Location ..\..

# 4. (Re)démarrer le détecteur avec le nouveau modèle
docker compose up -d --wait --wait-timeout 60 ml-detector
```

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
```

**Résultats vérifiés sur ce poste :**

| Service | Résultat |
|---|---|
| waf | 37 passés |
| remediation-engine | 19 passés |
| ml-detector | 8 passés |
| rag-assistant | 9 passés, **1 échec** : `test_injected_instruction_in_a_document_is_wrapped_as_context` — le test écrit un fichier accentué que Windows encode par défaut en cp1252, que le code relit en UTF-8 strict (`path.read_text(encoding="utf-8")` dans `rag.py`). Fonctionne sur un système qui écrit en UTF-8 par défaut (Linux/macOS) ; à corriger pour Windows si besoin (forcer l'encodage à l'écriture du fixture, ou lire avec `errors="replace"`). |
| dashboard | 6 passés, `npm run build` réussit |

(`sh tools/check_no_plaintext_secrets.sh` nécessite un shell POSIX — non vérifié sur ce poste.)

## Secrets : consultation rapide

```powershell
Get-Content .secrets\demo_password        # un seul secret
Get-ChildItem .secrets | ForEach-Object { "$($_.Name): $(Get-Content $_.FullName)" }   # tous
```

---

## Dispositif officiel (deux PC, SOPS/age, Ansible, Ollama natif) — non vérifié sur ce poste

Prévu pour l'évaluation : Windows 11 + WSL2 sur le PC Hôte, Docker Desktop (RAM ≥ 32 Go recommandée),
Ansible dans WSL, `sops` et `age`, Ollama installé nativement (`ollama pull qwen2.5:7b-instruct` et
`ollama pull nomic-embed-text`). Point d'accès sans fil Windows : l'hôte est en général `192.168.137.1`.

```bash
sh tools/init_secrets.sh          # une fois : clé age + secrets chiffrés (SAUVEGARDEZ la clé privée hors dépôt)
sh tools/render_secrets.sh        # déchiffre dans .secrets/ (ignoré par git, monté comme Docker secrets)
cp .env.example .env              # HOST_IP, TRUSTED_PROXIES, NEVER_BAN (IP du PC Hôte)
ansible-playbook ansible/deploy.yml -e bootstrap=true   # 1er démarrage : tout SAUF le détecteur (pas encore de modèle)
python3 tools/smoke.py --base http://192.168.137.1 --secret-file .secrets/demo_password
```

Puis entraîner le détecteur (même principe que ci-dessus, avec `192.168.137.1` à la place de
`127.0.0.1`) et relancer `ansible-playbook ansible/deploy.yml` (sans `bootstrap`).

Entre deux essais de démo : `ansible-playbook ansible/reset-demo.yml`.

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

`services/` (un dossier par composant), `infra/` (Prometheus, Loki, Grafana), `ansible/`, `redteam/`
(scénarios d'attaque), `tests/e2e/` (banc d'essai natif et résultats), `tools/` (secrets, test de
fumée), `docs/`, `governance/` (EBIOS RM, PCA/PRA, NIS2/DORA). `.venv/` (environnement Python local,
ignoré par Git) et `services/ml-detector/data/*.csv` (jeux de trafic collectés) apparaissent une fois
le détecteur entraîné sur ce poste.

## Limites assumées

Pas de TLS ni de MFA ; WAF Python « CRS-lite » (sous-ensemble de règles, pas ModSecurity/Coraza) ; une
seule machine, aucune redondance ; chaîne d'approvisionnement non scannée ; détection ~15-20 s après le
début d'un flood ; sur un seul poste, le bannissement par IP ne peut être démontré fidèlement qu'avec
des identités simulées (voir « Essai sur un seul poste »), pas avec de vraies IP distinctes. Liste
complète et chiffrée dans `governance/ebios-rm.md`.
