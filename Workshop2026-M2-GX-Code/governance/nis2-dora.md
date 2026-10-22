# Cartographie NIS2 / DORA : ce que le prototype couvre, partiellement, ou pas

Document de travail pour le jury. Il ne prétend pas à une conformité : un prototype fictif de 4 jours ne peut pas être « conforme ». Il indique, pour chaque exigence, **ce que le dépôt fait réellement**, la preuve, et l'écart. Je ne suis pas juriste : les références ci-dessous (directive (UE) 2022/2555, règlement (UE) 2022/2554) doivent être vérifiées sur les textes officiels avant citation dans le dossier.

Lecture : **Couvert** = mécanisme implémenté ET testé ; **Partiel** = implémenté ou documenté mais limité ; **Hors périmètre** = non traité.

## NIS2 : mesures de gestion des risques (art. 21 §2, liste des mesures minimales)

| Exigence | Statut | Ce que fait le prototype | Preuve | Écart |
|---|---|---|---|---|
| a) Politiques d'analyse des risques et de sécurité des SI | Partiel | Analyse EBIOS RM (`governance/ebios-rm.md`) liée aux mesures du dépôt | `ebios-rm.md` | Pas de politique de sécurité formelle validée par une direction |
| b) Gestion des incidents | **Couvert** (technique) | Machine d'états DETECTED → … → RECOVERED / CONTAINED / ESCALATED, audit JSONL, runbooks | `services/remediation-engine`, `docs/runbooks.md` | Pas de processus humain d'astreinte, pas d'exercice répété |
| c) Continuité des activités, sauvegardes, reprise, gestion de crise | Partiel | Sauvegarde/restauration PostgreSQL (Ansible), reprise automatique du service, vérification par transaction | `governance/pca-pra.md`, `ansible/` | Une seule machine, pas de site secondaire, sauvegarde sur le même hôte |
| d) Sécurité de la chaîne d'approvisionnement | **Écart** | Versions épinglées uniquement | `requirements.txt` | Aucun scan, aucune signature (R8 non traité) |
| e) Sécurité de l'acquisition, du développement et de la maintenance, gestion des vulnérabilités | Partiel | Tests automatisés par composant, requêtes paramétrées, WAF | suites de tests | Pas de SAST/DAST, pas de processus de correctifs |
| f) Évaluation de l'efficacité des mesures | Partiel | Scénario d'attaque rejoué (3 répétitions sous Docker, 300 à 500 req/s, verdict automatique), métriques avant/pendant/après, tests de non-régression | `tests/rehearsals/`, `tests/e2e/results/` | Pas d'audit externe ni de test d'intrusion indépendant |
| g) Hygiène informatique de base et formation | Hors périmètre | — | — | — |
| h) Cryptographie et chiffrement | **Écart** | Hachage scrypt, JWT signé, secrets chiffrés au repos (SOPS+age, cycle de chiffrement et déploiement Ansible exécutés) | `tools/`, `secrets/secrets.enc.yaml` | **Pas de TLS** en transit (écart assumé, R10) |
| i) Sécurité des ressources humaines, contrôle d'accès, gestion des actifs | Partiel | Rôles SQL minimaux, contrôle de propriété côté API, jetons d'administration distincts | `services/payment-api`, tests | Pas de revue périodique des accès, pas d'inventaire d'actifs formel |
| j) MFA / communications sécurisées | **Partiel** | **Utilisateurs du portail de paiement** : trois étapes, identifiant, reconnaissance faciale (caméra du PC Hôte), mot de passe ; ticket facial signé à usage unique vérifié côté serveur. Habilitations par rôles et permissions ; journal d'audit | `docs/biometric-auth.md`, `services/face-gate`, `services/auth-service`, `tests/e2e/face_flow.py` | **Comptes d'administration : mot de passe seul** (choix assumé, R16) ; pas de détection de vivacité ; **pas de TLS** (R10) ; taux d'erreur du visage non mesurés ; AIPD/RGPD à faire |

## NIS2 : notification d'incident (art. 23)

Le texte prévoit une alerte précoce, une notification d'incident puis un rapport final, dans des délais très courts (de l'ordre de 24 h pour l'alerte précoce : à vérifier sur le texte). Le prototype **ne notifie personne** ; il produit en revanche les éléments dont une notification a besoin : horodatage de détection, source (IP), classe de l'incident, actions entreprises, durée, résultat de la vérification. Ces éléments sont dans le journal d'audit du moteur de remédiation et dans le tableau de bord. Le jalon « décider si l'incident est notifiable » reste une décision **humaine**, volontairement.

## DORA (secteur financier, application à vérifier selon l'entité)

| Pilier | Statut | Correspondance | Écart |
|---|---|---|---|
| Gestion du risque lié aux TIC | Partiel | Analyse EBIOS RM, cartographie des composants, journalisation | Pas de cadre de gouvernance validé par un organe de direction |
| Gestion, classification et notification des incidents liés aux TIC | Partiel | Classification technique (disponibilité / compromission / inconnu), chronologie complète | Pas de grille de gravité réglementaire ni de gabarits de déclaration |
| Tests de résilience opérationnelle numérique | **Partiel, avec preuves** | Scénario d'attaque reproductible (`tools/rehearsal.py`), rejoué 3 fois avec mesure du RTO (reprise 21 à 29 s après le début de l'attaque) ; sauvegarde et restauration de la base exécutées (Ansible, 19 s) sur une base de démonstration | Pas de test d'intrusion piloté par la menace (TLPT) |
| Risque lié aux prestataires TIC tiers | **Écart** | Images publiques utilisées sans évaluation | Aucun registre des prestataires, aucune clause de sortie |
| Partage d'informations | Hors périmètre | — | — |

## Ce qu'il faut retenir pour le jury

1. Le prototype démontre surtout deux choses exigées par ces textes : **détecter et contenir** automatiquement, et **prouver la reprise** (transaction réelle + invariant comptable), avec une traçabilité complète.
2. Il laisse volontairement à des humains ce qui engage la responsabilité : décider d'une notification, accepter un risque, escalader une compromission.
3. Les écarts (TLS, MFA, chaîne d'approvisionnement, site de secours) sont listés ici plutôt que cachés : ils sont les premiers sujets d'une feuille de route.
