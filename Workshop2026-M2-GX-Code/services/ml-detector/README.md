# ml-detector : détection d'anomalies (domaine IA / Data)

## Rôle dans la chaîne
`Prometheus --(8 métriques / 5 s)--> ml-detector --(POST /v1/incidents)--> remediation-engine`

Le détecteur **décide qu'il y a une anomalie** et la qualifie grossièrement. Il n'agit jamais
sur les conteneurs : seul le moteur de remédiation le fait, avec une liste d'actions fermée.

## Méthode
- **Features** (`features.py`) : débit total, débit de l'IP la plus active, latence p95, ratios 5xx
  et 4xx, CPU, connexions actives. `features.py` est aussi le **contrat de métriques**
  que l'infra doit exposer. La mémoire du processus en a été retirée : dans un processus long-vivant
  elle varie à peine en fonctionnement normal, si bien qu'un seul relevé à son maximum observé
  suffisait à dominer le score d'isolation et à gonfler le seuil bien au-delà de ce qu'une vraie
  attaque atteint (vérifié en pratique).
- **Modèle** (`model.py`) : `log1p` sur les variables asymétriques, `StandardScaler`,
  `IsolationForest` (300 arbres). Non supervisé : entraîné uniquement sur du trafic normal.
- **Score** : `min(1, 0.7 × score_brut / seuil_brut)`. Le seuil brut est le quantile 99,9 % des scores
  d'un jeu de validation normal séparé. Découpage par blocs alternés (7 blocs sur 10 en entraînement,
  3 en validation, sur toute la durée de l'enregistrement), pas un simple coupage tête/queue : sinon
  une période d'inactivité ajoutée en fin d'enregistrement (voir README racine, « Entraîner le
  détecteur ») finit entièrement en validation, et le modèle n'apprend jamais que le calme est normal
  (vérifié en pratique : un vrai repos de la plateforme scorait alors presque aussi anormal qu'une
  attaque). `0.70` = « plus anormal que 99,9 % du trafic normal ». Ce changement de convention
  remplace les valeurs d'exemple 0.91 / 0.70 de l'itération 2 : le contrat JSON reste identique.
- **Anti faux positifs** (`gate.py`) : il faut 3 échantillons sur 4 au-dessus du seuil (~10-20 s), puis
  un seul incident par épisode ; réarmement après 6 échantillons calmes.
- **Qualification** (`classify`) : heuristique documentée sur les features qui dépassent leur p99
  normal. `availability` (flood, saturation), `compromise` (4xx anormaux à débit normal : scan,
  brute force, injection), sinon `unknown`. Le moteur ne doit **pas** traiter une `compromise`
  comme une simple panne.

## Utilisation
```bash
pip install -r requirements.txt
pytest tests                                     # 8 tests, ~5 s

# Développement, sans la stack : données SIMULÉES
python train.py --out ../../models/iforest.dev-simulated.joblib
python evaluate.py --model ../../models/iforest.dev-simulated.joblib

# Avec la vraie stack (plus il y a de données, mieux c'est ; inclure des périodes SANS trafic) :
python ../../redteam/normal_traffic.py --base http://192.168.137.1 --minutes 120   # >= 2 h, rafales incluses
python collect.py --prom http://localhost:9090 --minutes 120 --out data/normal.csv
python train.py --csv data/normal.csv --out ../../models/iforest.joblib
# après une attaque de test, exporter avec la fenêtre étiquetée puis :
python collect.py --prom http://localhost:9090 --minutes 20 --label-from <ISO> --label-to <ISO> --out data/labeled.csv
python evaluate.py --model ../../models/iforest.joblib --csv data/labeled.csv
```
Le compose monte `models/iforest.joblib`. Le modèle simulé est volontairement nommé
`iforest.dev-simulated.joblib` pour ne jamais partir en démo par mégarde.

## Résultats : ce qu'ils valent
Les chiffres ci-dessous viennent du **simulateur** (`simulate.py`), pas de la plateforme. Ils prouvent que
la chaîne fonctionne ; ils ne mesurent pas la performance réelle. À refaire sur données réelles.

| Test (simulé) | Résultat |
|---|---|
| 3 h de trafic normal avec rafales légitimes | 0 faux incident |
| 20 floods 120-600 req/s | 20/20 détectés, délai médian 10 s, max 15 s |
| 10 floods faibles 60-120 req/s | 10/10 détectés, délai médian 15 s, max 25 s |

## Résultats sur la plateforme réelle (banc d'essai natif, voir `tests/e2e/results/README.md`)
Entraînement sur **15 min de trafic légitime actif** (177 mesures) puis **5 min d'inactivité** (61 mesures) : c'est **peu**
(le README du simulateur recommande ≥ 2 h). Résultats :

| Essai réel | Résultat |
|---|---|
| Flood 300 req/s, 3 exécutions | 3/3 détectés, 26,2 / 26,5 / 26,6 s après le début (3 échantillons sur 4, tick de 5 s) |
| Injection / scan (37 requêtes) | pas d'incident ML (score 0,55 < 0,70) : traité par le WAF et l'alerte SIEM |
| Évaluation sur les données d'entraînement | 1 faux incident en 20 min (≈ 3/h) : **trop pour la production** |

**Défaut constaté et corrigé** : un premier modèle, entraîné sans phase d'inactivité, a ouvert 3 faux incidents « inconnus » pendant
les périodes sans trafic (score 0,70-0,707). Le trafic nul est un état normal pour une plateforme ; il doit figurer dans les
données d'entraînement. Un faux incident de classe inconnue ne déclenche **aucune action** (escalade seule), et un faux incident
« disponibilité » ne bannit que des sources à ≥ 30 req/s et ne redémarre qu'un service réellement dégradé.
**Ce modèle n'est pas livré** : la latence et le CPU d'une pile Docker Desktop diffèrent ; réentraînez sur votre pile
(voir `README.md` à la racine).

## Faux positifs : ce qu'on a constaté
Avec le quantile à 99,5 % et 1 h de données, le simulateur donnait jusqu'à ~2 faux incidents/heure,
tous sur des **rafales légitimes** (débit x2-3, latence normale). Le seuil reposait sur 1-2
échantillons de validation. Corrections : quantile à 99,9 %, au moins 2 h de données normales,
rafales légitimes présentes dans l'entraînement. Si des faux positifs persistent sur données réelles,
leviers dans l'ordre : plus de données, `DEBOUNCE_K=4`, exiger un symptôme de dégradation (latence
ou 5xx) en plus du score.

## Limites connues (à dire au jury)
- Un attaquant lent et discret (faible débit, sans dégradation) n'est pas détecté par ces features.
- Un trafic normal très différent de celui de l'entraînement (autre usage) fera dériver le modèle :
  il faut ré-entraîner.
- La qualification `availability`/`compromise` est une heuristique, pas une prédiction du modèle.
- L'IP source dépend de ce que le WAF voit réellement (NAT, header `X-Forwarded-For` de labo).
