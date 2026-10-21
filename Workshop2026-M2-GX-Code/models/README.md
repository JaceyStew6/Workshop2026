# Modèles

Le compose monte `models/iforest.joblib` (lecture seule) dans le conteneur `ml-detector`. Ce fichier est **produit
localement** par `services/ml-detector/train.py` et exclu de Git (`.gitignore`) : il dépend de l'hôte et de la pile
sur lesquels le trafic a été collecté. Sans lui, le détecteur ne démarre pas (premier déploiement :
`ansible-playbook ansible/deploy.yml -e bootstrap=true` démarre tout le reste).

Procédure : `README.md` à la racine, section « Entraîner le détecteur » (`tools/training_session.py`, ~2 h 12 de
trafic avec phases actives et inactives, puis `collect.py` et `train.py`).

Modèle courant sur le poste de développement : entraîné le 2026-10-20 sur 1 609 échantillons (132 min), 7 mesures,
`scikit-learn==1.5.2` (même version que l'image : un modèle entraîné avec une autre version peut ne pas se recharger).
Un redémarrage du PC ne l'invalide pas ; un changement de l'hôte ou de la plateforme peut déplacer la ligne de base
(vérifier que le score reste entre 0,40 et 0,58 au repos, sinon réentraîner).

Pour un essai de développement sans la stack : `cd services/ml-detector && python train.py --out ../../models/iforest.dev-simulated.joblib`
(données simulées, jamais à utiliser en démonstration).
