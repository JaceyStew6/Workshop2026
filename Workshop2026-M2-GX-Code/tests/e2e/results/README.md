# Résultats d'exécution de bout en bout (banc d'essai NATIF)

> **Résultats plus récents, sous Docker** (détecteur entraîné sur 132 min, 3 répétitions réussies, 300 à 500 req/s) : voir `tests/rehearsals/README.md`. Le présent document décrit le banc d'essai NATIF antérieur (sans Docker) ; ses chiffres de détection (≈ 26 s) correspondent à un ancien modèle entraîné sur 20 min.


**Ce que ces résultats prouvent, et ce qu'ils ne prouvent pas.** Ils ont été produits dans un environnement de travail SANS Docker : les mêmes services Python (auth, paiement, WAF), la même base PostgreSQL, le même moteur de remédiation et le même détecteur ont tourné comme **processus natifs** sur une seule machine ; seul le contrôleur de redémarrage est remplacé (`tests/e2e/run_remediation.py` relance un processus au lieu d'appeler Docker). L'« attaquant » est une adresse locale (192.168.137.20) sur la même machine, qui partage donc le processeur avec la plateforme. Ils ne remplacent PAS un essai sur le PC Hôte avec Docker Desktop et un vrai PC Attaquant : ils démontrent la **logique** et la **chaîne complète**, pas les performances de la configuration finale.

## Scénario 1 : saturation applicative (`flood-1`, `flood-2`, `flood-3`)

300 req/s sur `/api/fees/quote` pendant 75 s, depuis une source unique, pendant qu'un trafic légitime (5 sources, ~14 req/s) continue. Script : `tests/e2e/e2e_scenario.py`. Aucune intervention humaine entre le lancement et la fin.

| Exécution | Détection après le début | Détection → « rétabli » | Début de l'attaque → « rétabli » | Latence médiane avant | Pire latence pendant | Médiane après | Mesures « hors état normal » | Transaction pendant l'attaque | Transaction après |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 26,2 s | 13,6 s | 39,7 s | 117 ms | 2418 ms | 145 ms | 10 | réussie | réussie |
| 2 | 26,5 s | 16,3 s | 42,8 s | 120 ms | 2072 ms | 143 ms | 14 | réussie | réussie |
| 3 | 26,6 s | 13,3 s | 39,9 s | 121 ms | 2018 ms | 117 ms | 10 | réussie | réussie |

Déroulé identique à chaque fois : alerte du détecteur (score 0,704 pour un seuil de 0,70) → classe « availability » → bannissement de l'IP source (≥ 30 req/s) → le service redevient rapide → vérification : devis, connexion, paiement entre deux comptes de test, relecture, cohérence du grand livre, puis 8 s d'observation du chemin **public** → `RECOVERED`. Le restart n'a **pas** été nécessaire dans ces trois exécutions.

Lecture honnête :
- Les ~26 s de détection comprennent la fenêtre d'observation (3 échantillons anormaux sur 4, un tick toutes les 5 s) ; c'est le principal levier d'amélioration (au prix de plus de faux positifs).
- « Après » est un peu plus lent qu'« avant » car l'attaquant, banni, continue d'envoyer des requêtes que le WAF doit refuser (≈ 9 000 refus en 75 s) sur la même machine.
- La latence « avant » (~120 ms) est celle de la sonde publique de cette machine : elle ne se transpose pas à Docker Desktop.

## Scénario 1 bis : attaquant impossible à bannir (`flood-unbannable`)

Même flood, mais depuis l'adresse du PC Hôte (jamais bannie, garde-fou anti-verrouillage). C'est le cas d'un attaquant dont l'adresse est masquée (risque R7 : NAT de Docker Desktop).

Résultat : bannissement impossible → « service toujours dégradé » → **un** redémarrage du service de paiement → quelques secondes de répit → l'attaque reprend → l'observation de 8 s du chemin public échoue (`0/8`) → **`ESCALATED` après 49 s** (escalade humaine). La transaction de contrôle du moteur sur le chemin interne réussit, mais le moteur ne déclare pas « rétabli » tant que les clients ne le sont pas.

**Défaut trouvé puis corrigé pendant ces essais** : la première version ne vérifiait que le chemin interne, puis 3 devis publics consécutifs. Elle déclarait `RECOVERED` après un répit de quelques secondes, alors que le service retombait aussitôt (33 mesures dégradées). La vérification impose maintenant 8 s d'observation continue du chemin public.

## Scénario 2 : injection / scan (SQLi, traversée, XSS, `sqlmap` en User-Agent)

37 requêtes malveillantes depuis 192.168.137.20 : **37 refus 403 par le WAF** (règles par signature), aucun passage jusqu'à l'API. Le détecteur ML ne déclenche pas d'incident (score 0,55 < 0,70) : c'est attendu, ce scénario relève du WAF et de l'alerte SIEM. L'expression de l'alerte `WafSignatureBlocks` a été **évaluée sur Prometheus** après l'attaque et renvoie bien un résultat (≈ 40 blocages/min). Les règles ont été validées avec `promtool`. Grafana/Alertmanager n'ont pas été exécutés.

**Défaut trouvé puis corrigé** : les compteurs `waf_blocked_total{reason="signature"}` et `auth_login_total{result="failure"}` n'existaient qu'à leur premier événement ; or `increase()` et `rate()` ignorent la première valeur d'une série. La toute première rafale d'une instance fraîche aurait donc échappé aux alertes. Les séries sont désormais créées à 0 au démarrage.

## Faux positifs observés (à ne pas cacher)

Pendant ces essais, 3 incidents « inconnus » (score 0,70 à 0,707, au seuil) ont été ouverts **sans attaque**, tous pendant des périodes sans trafic ou avec forte charge de la machine (installation de paquets, compilation). Le modèle avait été entraîné uniquement sur du trafic actif : l'état « plateforme inactive » lui paraissait atypique. Le moteur a réagi **sans danger** (classe inconnue → aucune action automatique, escalade). Correction : réentraînement avec 5 min d'inactivité ajoutées ; aucun faux incident pendant les ≈ 6 minutes d'inactivité observées ensuite (fenêtre **trop courte pour conclure** ; l'évaluation sur les données d'entraînement donne encore ≈ 1 faux incident en 20 min). Voir `services/ml-detector/README.md`.

## Reproduire

```
RUN=/tmp/ra-run sh tests/e2e/stack.sh start      # pile native (voir tests/e2e/00_native_db.sh pour la base)
RUN=/tmp/ra-run python3 tests/e2e/e2e_scenario.py --out tests/e2e/results/mon-essai
```
Entre deux essais, débannir l'attaquant : `DELETE /v1/bans/192.168.137.20` sur l'API d'administration du WAF.
