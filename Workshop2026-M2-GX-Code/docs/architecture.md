# Architecture de PROJECT RESILIENCE-ALPHA

## Vue d'ensemble
La plateforme est un SI de paiement fictif en microservices conteneurisés, entouré d'une chaîne de
cyber-résilience : observabilité, détection ML, remédiation automatique et assistant opérateur.

Flux métier : client -> **WAF** (port 80) -> `frontend` (portail), `auth-service` (route `/auth/`),
`payment-api` (route `/api/`) -> **PostgreSQL**.

Flux de résilience : Prometheus collecte les métriques (WAF, payment-api, auth-service, cAdvisor) ->
**ml-detector** calcule un score d'anomalie toutes les 5 s -> en cas d'anomalie soutenue il envoie un
incident à **remediation-engine** -> le moteur exécute des actions de la liste fermée (bannir une IP au
WAF, redémarrer `payment-api`) puis **vérifie par une vraie transaction** avant de déclarer le service rétabli.

## Réseaux
- `edge` : seul le WAF y est publié (port 80 sur l'IP du hotspot, 192.168.137.1).
- `app` (internal) : frontend, auth-service, payment-api, postgres, WAF, Prometheus (scrape).
- `ops` (internal) : Prometheus, Loki, Promtail, ml-detector, remediation-engine, proxys Docker, cAdvisor, WAF (écouteurs 8081 sonde et 8082 admin).
- `mgmt` : Grafana (127.0.0.1:3000), dashboard (127.0.0.1:8088), assistant RAG (127.0.0.1:8090). Jamais joignable depuis le PC Attaquant.

## Composants et responsabilités
- **WAF** (`services/waf`) : reverse proxy, règles de signature (SQLi, XSS, traversée, RCE, scanners) avec score d'anomalie, liste de bans avec TTL (API d'admin authentifiée, port 8082), métriques `waf_requests_total{client_ip,status}`, journaux JSON pour le SIEM. Il ne bloque PAS sur le débit : cette décision appartient à la chaîne ML.
- **auth-service** : JWT HS256 (15 min), mots de passe scrypt, verrouillage après 5 échecs en 5 min.
- **payment-api** : paiements simulés avec contrôle de propriété du compte source, idempotence, invariant comptable (somme des soldes constante). Endpoint public coûteux `/api/fees/quote` = surface du scénario de saturation.
- **PostgreSQL** : rôles distincts à privilèges minimaux (`auth_svc`, `payment_svc`).
- **ml-detector** : Isolation Forest sur 8 métriques, déclenchement 3 échantillons sur 4, un incident par épisode.
- **remediation-engine** : machine à états DETECTED, DECIDING, REMEDIATING, VERIFYING, RECOVERED / CONTAINED / ESCALATED. Cibles autorisées par configuration, budget de redémarrages, accès Docker par proxy filtré.
- **dashboard** : état perçu du service (up / degraded / down) avant, pendant et après l'incident, timeline des étapes.
- **Assistant RAG** : répond aux questions des opérateurs à partir de `docs/` ; lecture seule, aucun accès au moteur de remédiation.
- **Secrets** : SOPS + age dans Git, rendus en fichiers `.secrets/` puis montés comme Docker secrets.

## Santé et seuils importants
- Service « up » : devis public en HTTP 200 sous 500 ms. « degraded » : 200 mais plus lent. « down » : erreur ou délai dépassé.
- Seuil d'anomalie : score >= 0,70 (plus anormal que 99,9 % du trafic normal d'entraînement).
- Un ban dure 600 s par défaut (plafond 3600 s) et ne vise jamais l'IP du PC Hôte.
- Au plus 3 redémarrages de `payment-api` par fenêtre de 5 minutes.
