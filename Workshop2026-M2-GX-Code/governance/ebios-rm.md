# Analyse de risques EBIOS Risk Manager : PROJECT RESILIENCE-ALPHA

Périmètre : la plateforme de paiement FICTIVE décrite dans `docs/architecture.md`, exécutée sur un PC Hôte (Windows, Docker Desktop, WSL2) joint par un PC Attaquant via le point d'accès sans fil du PC Hôte. Aucune donnée réelle. Échelles : gravité G et vraisemblance V de 1 à 4 ; niveau de risque = G × V (≥ 12 critique, 8-11 élevé, 4-7 moyen, ≤ 3 faible).

## Atelier 1 : cadrage et socle de sécurité

### Valeurs métier
| Id | Valeur métier | Pourquoi elle compte |
|---|---|---|
| VM1 | Exécution des paiements | Chaque minute d'arrêt retarde les opérations des partenaires et érode la confiance (sujet, §1). |
| VM2 | Intégrité du grand livre | Un paiement déplace de l'argent, il n'en crée pas : la somme des soldes est un invariant vérifiable (`/api/ledger/integrity`). |
| VM3 | Contrôle d'accès | Seul le propriétaire d'un compte peut le débiter (contrôle côté API). |
| VM4 | Traçabilité | Journaux WAF, audit du moteur de remédiation et alertes SIEM permettent l'investigation. |
| VM5 | Confidentialité des données clients | Fictives ici, mais traitées comme réelles par conception (aucun mot de passe journalisé, hachage scrypt). |

### Biens supports
payment-api, auth-service, PostgreSQL, WAF, remediation-engine, ml-detector, proxys Docker, Prometheus/Loki/Grafana, secrets (SOPS+age), PC Hôte (Docker Desktop / WSL2), réseau du point d'accès.

### Événements redoutés
| Id | Événement redouté | Valeur | G |
|---|---|---|---|
| ER1 | Paiement indisponible plus de 5 minutes | VM1 | 4 |
| ER2 | Écriture frauduleuse ou incohérence du grand livre | VM2 | 4 |
| ER3 | Divulgation de comptes ou d'identifiants | VM3, VM5 | 3 |
| ER4 | Prise de contrôle du moteur de remédiation (droits élevés sur les conteneurs) | VM1, VM2 | 4 |
| ER5 | Perte de traçabilité (journaux supprimés ou illisibles) | VM4 | 3 |

### Socle de sécurité : écarts assumés
| Mesure de référence | État | Commentaire |
|---|---|---|
| Chiffrement du transport (TLS) | **Écart** | HTTP en clair sur le réseau du point d'accès. Choix de prototype (pas d'autorité de certification en 4 jours). Atteinte à la confidentialité des jetons en transit : voir R10. |
| Authentification forte (MFA) | Écart | Hors périmètre prototype. |
| Gestion des secrets | Conforme | SOPS + age, Docker secrets, aucun secret dans l'archive (`tools/check_no_plaintext_secrets.sh`). |
| Journalisation | Conforme | Journaux JSON WAF et audit du moteur, centralisés dans Loki (chaîne Promtail → Loki **vérifiée en direct** : un événement d'audit y apparaît en moins de 15 s). Les corps de requête et en-têtes d'authentification ne sont jamais journalisés. Limite : après un redémarrage du PC, les journaux de la session précédente ne sont pas tous retransmis. |
| Cloisonnement réseau | Conforme | Réseaux `edge`, `app` (internal), `ops` (internal), `mgmt` ; seul le WAF est exposé. |
| Moindre privilège | Conforme | Rôles SQL distincts, conteneurs `cap_drop: ALL`, systèmes de fichiers en lecture seule, utilisateur non root. |
| Mises à jour / analyse de vulnérabilités des images | **Écart** | Versions épinglées, mais aucun scan automatique : voir R8. |

## Atelier 2 : sources de risque et objectifs visés
| Id | Source de risque | Objectif visé | Pertinence |
|---|---|---|---|
| SR1 | Attaquant opportuniste (script automatisé) | Rendre le service indisponible | Forte |
| SR2 | Attaquant ciblé à but lucratif | Fraude, extraction de données | Forte |
| SR3 | Initié ou erreur d'exploitation | Détournement de privilèges, mauvaise manipulation | Moyenne |
| SR4 | Compromission de la chaîne d'approvisionnement (images, paquets) | Code malveillant dans la plateforme | Moyenne |

## Atelier 3 : scénarios stratégiques (résumé)
- SS1 : SR1 sature un endpoint public coûteux pour atteindre ER1. Chemin direct (aucune partie prenante intermédiaire).
- SS2 : SR2 exploite une injection ou un accès usurpé pour atteindre ER2/ER3.
- SS3 : SR2 ou SR3 vise le moteur de remédiation, plus petite surface pour obtenir des droits élevés (ER4), donc chemin attractif.
- SS4 : SR4 introduit du code via une image ou un paquet public (partie prenante : fournisseurs d'images et de dépendances).

## Atelier 4 : scénarios opérationnels et mesures
| Risque | Scénario opérationnel | G | V init. | Niveau init. |
|---|---|---|---|---|
| R1 | **Saturation applicative** : flood de `/api/fees/quote` (public, coûteux) depuis une IP | 4 | 4 | 16 critique |
| R2 | **Injection** SQL/XSS/traversée dans les paramètres | 4 | 3 | 12 critique |
| R3 | **Force brute** sur `/auth/token`, ou verrouillage volontaire d'un compte légitime | 3 | 3 | 9 élevé |
| R4 | **Détournement du moteur de remédiation** (appel illégitime à son API, ou usage du socket Docker pour sortir du périmètre) | 4 | 2 | 8 élevé |
| R5 | **Surface d'observabilité** : cAdvisor lit l'hôte, Promtail lit les journaux de tous les conteneurs | 3 | 2 | 6 moyen |
| R6 | **Faux positif du ML** déclenchant des bannissements ou redémarrages à tort (disponibilité auto-infligée) | 3 | 3 | 9 élevé |
| R7 | **Usurpation de l'IP source** : en-tête falsifié pour contourner un ban ou faire bannir une victime ; masquage de l'IP par la NAT de Docker Desktop | 3 | 3 | 9 élevé |
| R8 | **Chaîne d'approvisionnement** : image ou paquet compromis | 4 | 2 | 8 élevé |
| R9 | **Secrets** exposés (dépôt, archive, variables d'environnement) | 3 | 3 | 9 élevé |
| R10 | **Interception** du trafic en clair (jetons JWT) sur le réseau du point d'accès | 3 | 2 | 6 moyen |

### Mesures implémentées et preuves
| Risque | Mesures (dans le dépôt) | Preuve vérifiable |
|---|---|---|
| R1 | Chaîne ML → remédiation : bannissement de la source (> 30 req/s), redémarrage conditionnel, **vérification par transaction réelle** avant « rétabli » ; capacité de `payment-api` bornée (`cpus: 0.5`, pool de 3 connexions, attente maximale de 0,4 s) pour que la saturation soit visible et franche (HTTP 503 pour devis et virements) | 3 répétitions sous Docker (`tests/rehearsals/`, 300 à 500 req/s : détection en 12 à 17 s, reprise en 21 à 29 s pendant que l'attaque continue, 100 % de virements réussis ensuite), banc natif (`tests/e2e/results/`), `services/remediation-engine/tests` (19 tests) |
| R2 | Requêtes SQL **paramétrées** (aucune concaténation), WAF à score d'anomalie (SQLi, XSS, traversée, RCE, scanners), validation Pydantic des entrées, rôle SQL à droits minimaux | `services/waf/tests` (37 tests dont 17 attaques bloquées et 8 requêtes légitimes laissées passer), test manuel : `payment_svc` ne peut pas lire `users` |
| R3 | Verrouillage après 5 échecs en 5 min, hachage scrypt, réponse identique pour utilisateur inconnu ; alerte SIEM `AuthBruteForce` | Test fonctionnel : 4 × 401 puis 429 |
| R4 | API du moteur réservée au détecteur (jeton comparé en temps constant) ; **liste fermée d'actions** (`BAN_IP`, `RESTART_SERVICE`) ; cibles autorisées par configuration ; label `resilience.remediable=true` vérifié avant tout redémarrage ; proxy Docker filtré (aucun `exec`, `create`, `delete`, image, réseau, volume) ; budget de 3 redémarrages par fenêtre de 5 min ; réseau `ops` interne | Tests : cible hors liste rejetée, identifiant malformé rejeté, classe hors énumération rejetée, budget respecté entre incidents |
| R5 | Accès en lecture seule (`:ro`) ; proxy `docker-ro` pour Promtail (`POST=0`, `EXEC=0`, `VOLUMES=0`, `IMAGES=0` ; `CONTAINERS=1` et `NETWORKS=1` en lecture : Promtail a besoin de lister les réseaux pour étiqueter les conteneurs, sans quoi Loki ne reçoit rien) ; cAdvisor sur le réseau `ops` interne (sous Docker Desktop il ne voit que l'hôte, jamais les conteneurs individuels) | Revue de `docker-compose.yml` ; Promtail → Loki vérifié en direct |
| R6 | Déclenchement 3 échantillons sur 4, un incident par épisode, quantile à 99,9 % sur jeu de validation, entraînement sur 132 min de trafic réel (phases actives avec rafales légitimes et phases d'inactivité, `tools/training_session.py`) ; classe « inconnue » = aucune action automatique ; bannissements bornés (TTL, 100 actifs max, IP du PC Hôte jamais bannie) ; budget de redémarrages ; filtre de `train.py` qui rejette les lignes à taux d'erreur > 30 % | `services/ml-detector/tests`, évaluation (`services/ml-detector/README.md`). **Incident réel constaté** pendant la mise au point : un modèle trop peu entraîné (20 min) a classé du trafic légitime en attaque et fait bannir la passerelle Docker, donc tout le trafic de l'hôte, pendant 10 min ; il a aussi contaminé un jeu d'entraînement. Corrigé (entraînement long, filtre anti-contamination, retrait de la variable mémoire). Au repos, score 0,40-0,58 pour un seuil de 0,70 |
| R7 | `X-Forwarded-For` ignoré par défaut ; accepté seulement depuis des proxys listés dans `TRUSTED_PROXIES` ; bans par IP unique (pas de réseau) ; métriques à cardinalité bornée | Test du WAF. **Constaté sur un seul poste sous Docker Desktop** : le WAF voit la passerelle du réseau `edge` (`172.30.10.1`) pour tout le trafic venant de l'hôte, attaquant compris ; un ban frappe alors tout le monde (vérifié). Contournement en laboratoire : `TRUSTED_PROXIES` + identités simulées (`--spoof-ip`), jamais sur le dispositif à deux PC. **Toujours à vérifier avec un vrai second PC** : quelle IP source voit le WAF ? |
| R8 | Versions épinglées dans les `requirements.txt` et les images, proxys officiels. La vérification des certificats TLS est **active par défaut** au build ; sur un réseau qui intercepte TLS elle peut être désactivée explicitement, pendant le build uniquement (`PIP_EXTRA_ARGS`, `NPM_STRICT_SSL` dans `.env`) : c'est une exposition à une interception pendant le build, à réserver à ce cas | **Aucun scan automatisé** : risque non traité, voir ci-dessous |
| R9 | SOPS + age, Docker secrets (fichiers, pas de variables d'environnement), `.gitignore`, contrôle automatique avant archive | Cycle complet exécuté sous WSL : `init_secrets.sh` (SOPS + age), déchiffrement par `ansible/deploy.yml`, déploiement réussi avec ces secrets ; `secrets.enc.yaml` vérifié chiffré, aucune clé privée dans le dépôt ; `tools/check_no_plaintext_secrets.sh` exécuté. Sur ce poste, la clé privée age est dans le répertoire personnel de la distribution WSL (`~/.config/sops/age/keys.txt`) : à sauvegarder hors dépôt |
| R10 | **Aucune mesure** (écart assumé) | — |

## Atelier 5 : risque résiduel et plan d'action
| Risque | Niveau initial | Niveau résiduel | Justification | Action recommandée à une direction |
|---|---|---|---|---|
| R1 | 16 critique | **6 moyen** (G2 × V3) | La gravité baisse car l'indisponibilité est écourtée et prouvée résolue ; la vraisemblance d'une attaque reste forte. Reste exposé à une attaque **distribuée** (plusieurs sources sous le seuil de 30 req/s) | Ajouter une limitation de débit globale et un CDN/anti-DDoS en amont ; en industriel, ne jamais compter sur l'hôte seul |
| R2 | 12 critique | 4 moyen | Défense en profondeur (paramétrage + WAF) ; le jeu de règles reste un sous-ensemble de CRS | Passer à ModSecurity/Coraza avec CRS complet ; tests d'intrusion |
| R3 | 9 élevé | 6 moyen | Le verrouillage protège le mot de passe mais **permet de verrouiller un compte légitime** (déni ciblé) | Verrouillage progressif par couple (compte, IP) ; MFA |
| R4 | 8 élevé | 4 moyen | `ALLOW_RESTARTS` du proxy Docker autorise aussi `stop` et `kill` ; la restriction vient du moteur (label), pas du proxy | Remplacer par un orchestrateur avec RBAC fin (Kubernetes, Nomad) ou un agent dédié ne sachant faire que `restart` |
| R5 | 6 moyen | 6 moyen | Accès large en lecture assumé pour l'observabilité | Isoler la collecte sur un hôte dédié |
| R6 | 9 élevé | 4 moyen | Le ML peut se tromper (un faux positif réel a banni toute la passerelle 10 min pendant la mise au point) ; les conséquences sont bornées (TTL, budgets, anti-lockout), pas supprimées. Après entraînement long : 0,44 % des échantillons normaux au-dessus du seuil, aucun incident au repos | Mode « suggestion » pendant une phase d'observation avant l'automatisation complète ; réentraîner après tout changement de l'hôte |
| R7 | 9 élevé | 6 moyen | Masquage de l'IP source par Docker Desktop **constaté** sur un seul poste (le WAF ne voit que la passerelle) ; non vérifié avec un second PC réel, d'où un niveau résiduel qui reste à confirmer | Valider avec un vrai PC Attaquant avant la démonstration ; sinon placer un reverse proxy natif qui transmet l'IP réelle |
| R8 | 8 élevé | 8 élevé | **Non traité** | Scan d'images (Trivy), signature, miroir interne de dépendances |
| R9 | 9 élevé | 3 faible | Contrôles testés | Rotation périodique, coffre (Vault) en production |
| R10 | 6 moyen | 6 moyen | **Écart assumé** | TLS partout (autorité de certification interne) avant tout usage réel |

Risques acceptés explicitement pour le prototype : R5, R10. Risque **non traité** et à signaler au commanditaire : R8.

## Pour le jury : lecture de l'arbitrage
Ce que nous avons choisi de protéger en priorité : **la disponibilité prouvée du paiement (VM1) et l'intégrité du grand livre (VM2)**, parce qu'ils sont mesurables par une transaction réelle et un invariant comptable. Ce que nous avons accepté de ne pas faire : TLS, MFA, scan d'images. La compromission d'un composant privilégié (R4) est le risque que la plateforme **introduit elle-même** en se défendant : c'est pourquoi le moteur est le composant le plus contraint du dépôt.
