# PCA / PRA : continuité et reprise de la plateforme RESILIENCE-ALPHA

Périmètre : une plateforme fictive sur **un seul hôte**. Ce document distingue ce qui est **automatique et mesuré** de ce qui est **procédural et non rejoué en conditions réelles**.

## 1. Objectifs

| Objectif | Valeur cible | Statut |
|---|---|---|
| RTO — attaque applicative (saturation) | ≤ 60 s entre la détection et la transaction de contrôle réussie | **Mesuré sous Docker, 3 fois** : 9,1 / 11,8 / 11,8 s de la détection à la reprise (21 à 29 s depuis le début de l'attaque), voir `tests/rehearsals/` ; exécution native antérieure dans `tests/e2e/results/`. Attaquant simulé sur la même machine |
| RTO — plantage d'un service | ≤ 90 s (redémarrage + attente de santé + vérification) | Couvert par les tests du moteur ; non mesuré sur Docker |
| RPO — base de paiement | = intervalle entre deux sauvegardes (`ansible/backup.yml`), **pas de réplication** | Cible déclarative, aucune planification automatique livrée |
| Invariant d'intégrité | Somme des soldes constante après toute reprise | Vérifié par la sonde (`/api/ledger/integrity`) |

Ces cibles sont des **choix d'équipe** à valider ; elles ne dérivent d'aucune exigence métier réelle.

## 2. PCA : ce qui maintient le service sans humain

1. **Détection** : le détecteur ML note la santé du service toutes les 5 secondes ; déclenchement sur 3 échantillons sur 4 au-dessus du seuil (12 à 17 s après le début d'une attaque, mesuré).
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
| S6 Perte de la clé age (secrets) | Humain | Régénérer tous les secrets (`FORCE=1 sh tools/init_secrets.sh`), supprimer les volumes (`docker compose down -v`, les mots de passe changent), redéployer ; les sessions JWT en cours sont invalidées | Non |
| S7 Caméra ou agent hôte indisponible | Message « service de reconnaissance indisponible » à la connexion au portail | Relancer `host-agent/run-agent.ps1` ou brancher une autre webcam ; récupération : `enroll_cli.py` depuis l'hôte. **Aucun utilisateur du portail ne peut se connecter pendant ce temps** ; back-office, sonde, scripts et jetons déjà émis (15 min) continuent | Non (échec fermé voulu) |

### Ordre de reconstruction (S5)
1. Installer Docker Desktop et préparer WSL (Ubuntu, `age`, `sops`, `ansible`, intégration Docker, utilisateur dédié, option de montage `metadata` : procédure exacte dans le README, « Déploiement officiel sous WSL »).
2. Récupérer le dépôt et la **clé privée age** (conservée hors du dépôt, par une personne désignée ; sur le poste actuel elle est dans `~/.config/sops/age/keys.txt` de la distribution WSL : à sauvegarder).
3. `ansible-playbook ansible/deploy.yml -e bootstrap=true` (déchiffre les secrets, construit, démarre), réentraîner ou récupérer le modèle du détecteur, puis `ansible-playbook ansible/deploy.yml`.
4. `ansible-playbook ansible/restore.yml` (dernière sauvegarde).
5. `python3 tools/smoke.py` puis contrôle de l'invariant.

## 4. Sauvegarde

- Outil : `ansible/backup.yml` (`pg_dump` format custom, 10 sauvegardes conservées, dossier `backups/` en mode 0700).
- Restauration : `ansible/restore.yml` coupe d'abord WAF et services écrivants, restaure, réapplique les droits SQL, redémarre, puis lance le test de fumée.
- **Mesuré sous Docker** : sauvegarde (`backup.yml`, quelques secondes, fichier `payments-*.dump` créé), restauration (`restore.yml`, 19 s, test de fumée réussi à la fin), remise à zéro de la démonstration (`reset-demo.yml`, 12 s).
- **Faiblesses assumées** : les sauvegardes sont sur le même hôte que la base ; elles ne sont pas chiffrées ; aucune planification (cron/timer) n'est livrée ; la restauration a été rejouée sur une base ne contenant que des données de démonstration, pas sur une base corrompue : le contrôle de l'invariant après restauration reste à faire dans ce cas (scénario S4).

## 5. Ce que nous ne promettons pas

- Aucune tolérance à la perte de l'hôte (pas de redondance).
- Aucune protection contre une attaque distribuée dont chaque source reste sous 30 req/s.
- Aucune garantie que le seuil du détecteur, calibré sur 132 min de trafic de cette pile, convienne à un trafic ou à un hôte différents : un simple redémarrage du PC a déjà déplacé la ligne de base. Le modèle doit être réentraîné après tout changement (`services/ml-detector/README.md`, procédure du README racine).

## 6. Exercices à répéter avant la démonstration

| # | Exercice | État |
|---|---|---|
| 1 | Attaque S1, trois fois de suite, en notant le RTO | **Fait sous Docker, attaquant simulé sur la même machine** (3/3 réussies, `tests/rehearsals/`). À refaire depuis un vrai PC Attaquant |
| 2 | Arrêt brutal de `payment-api` (S2) | À faire |
| 3 | Sauvegarde puis restauration (S4) avec contrôle de l'invariant | Sauvegarde et restauration **faites** (Ansible) ; contrôle sur base corrompue à faire |
| 4 | Attaque par injection (S3) : vérifier la contention **sans** redémarrage | Fait sur le banc natif (37/37 refusées) ; à rejouer sous Docker |
| 5 | Vérifier que le WAF voit bien l'adresse IP réelle du PC Attaquant derrière Docker Desktop (risque R7) | **À faire** : constaté sur un seul poste que le WAF ne voit que la passerelle |
