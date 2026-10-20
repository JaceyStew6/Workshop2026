# PCA / PRA : continuité et reprise de la plateforme RESILIENCE-ALPHA

Périmètre : une plateforme fictive sur **un seul hôte**. Ce document distingue ce qui est **automatique et mesuré** de ce qui est **procédural et non rejoué en conditions réelles**.

## 1. Objectifs

| Objectif | Valeur cible | Statut |
|---|---|---|
| RTO — attaque applicative (saturation) | ≤ 60 s entre la détection et la transaction de contrôle réussie | Mesuré en exécution native : voir `tests/e2e/results/` |
| RTO — plantage d'un service | ≤ 90 s (redémarrage + attente de santé + vérification) | Couvert par les tests du moteur ; non mesuré sur Docker |
| RPO — base de paiement | = intervalle entre deux sauvegardes (`ansible/backup.yml`), **pas de réplication** | Cible déclarative, aucune planification automatique livrée |
| Invariant d'intégrité | Somme des soldes constante après toute reprise | Vérifié par la sonde (`/api/ledger/integrity`) |

Ces cibles sont des **choix d'équipe** à valider ; elles ne dérivent d'aucune exigence métier réelle.

## 2. PCA : ce qui maintient le service sans humain

1. **Détection** : le détecteur ML note la santé du service toutes les secondes ; déclenchement sur 3 échantillons sur 4 au-dessus du seuil.
2. **Confinement** : bannissement de la ou des sources dont le débit dépasse 30 req/s (le trafic légitime d'autres sources n'est pas touché ; l'IP du PC Hôte n'est jamais bannie).
3. **Reprise** : si le service reste dégradé après le bannissement, redémarrage du seul conteneur autorisé, dans la limite de 3 redémarrages par fenêtre de 5 min.
4. **Preuve** : l'état « rétabli » n'est prononcé qu'après une **transaction réelle** (devis, authentification, paiement de la sonde entre deux comptes de test, relecture) **et** le contrôle de l'invariant du grand livre.
5. **Limites** : si la cause paraît être une compromission, le service est **contenu et jamais redémarré** (un redémarrage détruirait les preuves et pourrait réactiver une porte dérobée) ; l'incident est escaladé à un humain.

## 3. PRA : scénarios et procédures

| Scénario | Détection | Procédure | Automatique ? |
|---|---|---|---|
| S1 Saturation par une source | Détecteur ML | Chaîne ci-dessus | Oui |
| S2 Service planté | Sonde de santé + détecteur | Redémarrage ciblé + vérification | Oui |
| S3 Compromission suspectée | Règles WAF (signatures), alertes SIEM | Bannissement, isolement, **escalade** ; analyse humaine ; reconstruction | Partiel (contention auto, reprise humaine) |
| S4 Base corrompue ou invariant violé | Sonde (`ledger/integrity`) | `ansible-playbook ansible/restore.yml` après arrêt des écritures | Non (décision humaine) |
| S5 Perte de l'hôte | Humain | Reconstruire l'hôte, `ansible/deploy.yml`, restaurer la dernière sauvegarde | Non |
| S6 Perte de la clé age (secrets) | Humain | Régénérer tous les secrets (`tools/init_secrets.sh`), redéployer ; les sessions JWT en cours sont invalidées | Non |

### Ordre de reconstruction (S5)
1. Installer Docker et Ansible sur le nouvel hôte.
2. Récupérer le dépôt et la **clé privée age** (conservée hors du dépôt, par une personne désignée).
3. `tools/render_secrets.sh`, puis `ansible-playbook ansible/deploy.yml`.
4. `ansible-playbook ansible/restore.yml` (dernière sauvegarde).
5. `python3 tools/smoke.py` puis contrôle de l'invariant.

## 4. Sauvegarde

- Outil : `ansible/backup.yml` (`pg_dump` format custom, 10 sauvegardes conservées, dossier `backups/` en mode 0700).
- Restauration : `ansible/restore.yml` coupe d'abord WAF et services écrivants, restaure, réapplique les droits SQL, redémarre, puis lance le test de fumée.
- **Faiblesses assumées** : les sauvegardes sont sur le même hôte que la base ; elles ne sont pas chiffrées ; aucune planification (cron/timer) n'est livrée ; la restauration n'a **pas** été rejouée sur Docker dans cet environnement de travail. À tester sur le PC Hôte avant la démonstration.

## 5. Ce que nous ne promettons pas

- Aucune tolérance à la perte de l'hôte (pas de redondance).
- Aucune protection contre une attaque distribuée dont chaque source reste sous 30 req/s.
- Aucune garantie que le seuil du détecteur, calibré sur le trafic de ce banc d'essai, convienne à un trafic différent : le modèle doit être réentraîné sur le trafic réel du PC Hôte (`services/ml-detector/README.md`).

## 6. Exercices à répéter avant la démonstration

1. Attaque S1 depuis le PC Attaquant, trois fois de suite, en notant le RTO.
2. Arrêt brutal de `payment-api` (S2).
3. Sauvegarde puis restauration (S4) avec contrôle de l'invariant.
4. Attaque par injection (S3) : vérifier la contention **sans** redémarrage.
5. Vérifier que le WAF voit bien l'adresse IP réelle du PC Attaquant derrière Docker Desktop (risque R7).
