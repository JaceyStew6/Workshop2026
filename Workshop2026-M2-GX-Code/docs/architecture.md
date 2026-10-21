# Architecture de PROJECT RESILIENCE-ALPHA

## Vue d'ensemble
La plateforme est un SI de paiement fictif en microservices conteneurisés, entouré d'une chaîne de
cyber-résilience : observabilité, détection ML, remédiation automatique et assistant opérateur.

Flux métier : client -> **WAF** (port 80) -> `frontend` (portail et back-office), `face-gate` (route `/gate/`), `auth-service` (route `/auth/`),
`payment-api` (route `/api/`) -> **PostgreSQL**.

Flux de résilience : Prometheus collecte les métriques (WAF, payment-api, auth-service, cAdvisor) ->
**ml-detector** calcule un score d'anomalie toutes les 5 s -> en cas d'anomalie soutenue il envoie un
incident à **remediation-engine** -> le moteur exécute des actions de la liste fermée (bannir une IP au
WAF, redémarrer `payment-api`) puis **vérifie par une vraie transaction** avant de déclarer le service rétabli.

Flux des journaux : les conteneurs écrivent des journaux JSON -> **Promtail** les lit via `docker-ro`
(proxy Docker en lecture seule) -> **Loki** -> **Grafana** (panneau SIEM, requêtes `{service="waf"} | json`).

## Réseaux
- `edge` : seul le WAF y est publié (port 80 sur l'IP du hotspot, 192.168.137.1 ; 127.0.0.1 sur un poste de
  développement unique). Sous-réseau fixe `172.30.10.0/24` (passerelle `172.30.10.1`).
- `app` (internal) : frontend, auth-service, payment-api, postgres, WAF, Prometheus (scrape).
- `ops` (internal) : Prometheus, Loki, Promtail, ml-detector, remediation-engine, proxys Docker, cAdvisor, WAF (écouteurs 8081 sonde et 8082 admin).
- `mgmt` : `face-gate` (seul chemin vers l'agent caméra du PC Hôte, `host.docker.internal:8095`), Grafana (127.0.0.1:3000), dashboard (127.0.0.1:8088), assistant RAG (127.0.0.1:8090). Jamais joignable depuis le PC Attaquant.

## Composants et responsabilités
- **WAF** (`services/waf`) : reverse proxy, règles de signature (SQLi, XSS, traversée, RCE, scanners) avec score d'anomalie, liste de bans avec TTL (API d'admin authentifiée, port 8082), métriques `waf_requests_total{client_ip,status}`, journaux JSON pour le SIEM. Il ne bloque PAS sur le débit : cette décision appartient à la chaîne ML.
- **auth-service** : JWT HS256 (15 min), mots de passe scrypt, verrouillage après 5 échecs en 5 min.
- **payment-api** : paiements simulés avec contrôle de propriété du compte source, idempotence, invariant comptable (somme des soldes constante). Endpoint public coûteux `/api/fees/quote` = surface du scénario de saturation. Capacité volontairement bornée pour que la saturation soit visible : 0,5 CPU, pool de 3 connexions à la base, attente maximale de 0,4 s pour obtenir une connexion. Sous une attaque, devis **et** virements échouent alors franchement (HTTP 503) pour tous les clients, pas seulement l'attaquant, jusqu'à la remédiation.
- **face-gate** + **agent hôte** (`host-agent/`, caméra USB du PC Hôte) : authentification faciale du back-office, voyant ESP8266, inscription des visages. Voir `docs/biometric-auth.md`.
- **Habilitations** : rôles et permissions en base, portées par le JWT (`perms`) ; administration via `/auth/admin/*` et `/gate/*`.
- **PostgreSQL** : rôles distincts à privilèges minimaux (`auth_svc`, `payment_svc`, `gate_svc`).
- **ml-detector** : Isolation Forest sur 7 mesures lues dans Prometheus toutes les 5 s (débit total, débit de l'IP la plus active, latence p95 sur 60 s, ratios 4xx et 5xx, CPU du processus payment-api, connexions actives). Déclenchement : 3 échantillons sur 4 au-dessus du seuil de 0,70, un incident par épisode. Entraîné sur 132 min de trafic réel de cette pile (phases actives et inactives). Détection mesurée : 12 à 17 s après le début d'un flood.
- **remediation-engine** : machine à états DETECTED, DECIDING, REMEDIATING, VERIFYING, RECOVERED / CONTAINED / ESCALATED. Cibles autorisées par configuration, budget de redémarrages, accès Docker par proxy filtré.
- **dashboard** : état perçu du service (up / degraded / down) avant, pendant et après l'incident, timeline des étapes.
- **Assistant RAG** : répond aux questions des opérateurs à partir de `docs/` ; lecture seule, aucun accès au moteur de remédiation.
- **Secrets** : SOPS + age dans Git, rendus en fichiers `.secrets/` puis montés comme Docker secrets.

## Preuve de reprise (cinq étapes)
Avant de déclarer « service rétabli », le moteur rejoue le parcours d'un client réel avec un compte de sonde :
1. **devis** public ; 2. **connexion** ; 3. **paiement** entre deux comptes de test ; 4. **relecture** de ce paiement ;
5. **grand livre** : la somme des soldes de tous les comptes doit être restée exactement la même (un paiement déplace
de l'argent, il n'en crée ni n'en détruit ; si ce total bouge, des données sont corrompues).
Puis le chemin public doit rester rapide pendant 8 secondes consécutives. Si une étape échoue, le service n'est pas
déclaré rétabli et l'incident est escaladé à un humain.

## Une seule machine : ce que le WAF voit
Sous Docker Desktop, tout le trafic venant de l'hôte (navigateur, scripts, attaque lancée depuis le même PC)
arrive au WAF avec la même adresse : la passerelle `172.30.10.1`. Un bannissement viserait alors tout le monde.
Pour simuler des identités distinctes sur un seul poste, `TRUSTED_PROXIES=172.30.10.0/24` (fichier `.env`) fait
accepter l'en-tête `X-Forwarded-For` ; les scripts `redteam/` le posent avec `--spoof-ip` / `--spoof-ips`.
Ce mode ne doit **jamais** être activé sur le dispositif à deux PC (l'attaquant pourrait falsifier son adresse).

## Santé et seuils importants
- Service « up » : devis public en HTTP 200 sous 500 ms. « degraded » : 200 mais plus lent. « down » : erreur ou délai dépassé.
- Seuil d'anomalie : score >= 0,70 (plus anormal que 99,9 % du trafic normal d'entraînement). Au repos le score reste entre 0,40 et 0,58.
- Un ban dure 600 s par défaut (plafond 3600 s) et ne vise jamais l'IP du PC Hôte.
- Au plus 3 redémarrages de `payment-api` par fenêtre de 5 minutes.
