# Modèles

Le compose attend `models/iforest.joblib`, qui n'est PAS fourni : il doit être entraîné sur le trafic réel de votre pile
(voir `README.md` à la racine, section « Entraîner le détecteur sur VOTRE pile »).

Pour un essai de développement sans la stack : `cd services/ml-detector && python3 train.py --out ../../models/iforest.dev-simulated.joblib`
(données simulées, jamais à utiliser en démonstration).
