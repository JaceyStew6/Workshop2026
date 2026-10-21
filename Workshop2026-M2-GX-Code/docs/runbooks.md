# Runbooks opérateur

Les commandes ci-dessous se lancent depuis la racine du dépôt. Les commandes `docker compose` et `python`
fonctionnent depuis PowerShell ; les playbooks `ansible-playbook` se lancent depuis Ubuntu sous WSL
(`wsl -d Ubuntu-24.04`, voir README, « Déploiement officiel sous WSL »).

## Saturation
Symptômes : latence p95 de payment-api > 500 ms, taux de 5xx qui monte, devis et virements en erreur 503, une IP à débit anormal.
Réponse automatique : le moteur bannit la source (si > 30 req/s), attend le retour à la normale, redémarre
payment-api seulement si le service reste dégradé, puis vérifie par une transaction de contrôle. Mesuré : détection
12 à 17 s après le début de l'attaque, service rétabli 21 à 29 s après, alors que l'attaque continue.
Vérification manuelle : `.\.venv\Scripts\python.exe tools\smoke.py --base http://127.0.0.1` (ou `http://192.168.137.1` sur le point d'accès sans fil).
Escalade : si l'incident passe à ESCALATED, consulter le dashboard (http://127.0.0.1:8088), l'étape en échec et le journal d'audit du moteur.

## Ban
Un ban est temporaire (600 s). Les commandes passent par le conteneur du moteur de remédiation, seul à connaître le jeton d'administration du WAF :

Lister les bans :
`docker compose exec -T remediation-engine python3 -c "import urllib.request; tok=open('/run/secrets/waf_admin_token').read().strip(); print(urllib.request.urlopen(urllib.request.Request('http://waf:8082/v1/bans', headers={'x-admin-token': tok}), timeout=3).read())"`

Débannir une IP (par exemple une IP légitime bannie à tort) : même commande avec `method='DELETE'` et l'URL `http://waf:8082/v1/bans/<ip>`.
L'IP du PC Hôte et le bouclage local ne peuvent jamais être bannis. Un ban actif sur l'identité d'un attaquant simulé
empêche de la réutiliser pour un nouvel essai : changer d'identité ou la débannir.

## Brute force
Symptômes : alerte AuthBruteForce, réponses 401 puis 429 sur `/auth/token`. Le compte visé est verrouillé 5 minutes après 5 échecs. Conséquence connue : un attaquant peut verrouiller un compte légitime (déni de service ciblé). Action : identifier la source dans les journaux WAF (`event=waf`, `status=401`), la bannir si besoin.

## Injection
Symptômes : alerte WafSignatureBlocks, requêtes 403 avec identifiants de règles 942xxx (SQL), 941xxx (XSS), 930xxx (fichiers), 932xxx (commandes). Le WAF a déjà bloqué ces requêtes. Une tentative d'injection n'est PAS une panne : on ne redémarre rien. Conserver les journaux, identifier la source, vérifier que l'API ne construit aucune requête SQL par concaténation (elle utilise des paramètres liés), escalader pour investigation.

## Escalade
Un incident ESCALATED signifie que la reprise automatique n'a pas pu être prouvée dans le délai. Étapes :
1) lire l'incident (`GET /v1/incidents/<id>` ou dashboard) ;
2) identifier l'étape de la sonde en échec. La preuve de reprise a cinq étapes : devis, connexion, paiement, relecture, grand livre ;
3) le « grand livre » est la comptabilité de la base : la somme des soldes de tous les comptes doit rester exactement la même (un paiement déplace de l'argent, il n'en crée ni n'en détruit). S'il est incohérent, des données sont corrompues : ne PAS rouvrir le trafic, restaurer la sauvegarde (`ansible-playbook ansible/restore.yml`) ;
4) sinon redémarrer manuellement le composant fautif et relancer le smoke test.

## Anomalie sans signature (classe « inconnue »)
Symptômes : incident ESCALATED avec la classe `unknown` et l'action `NO_ACTION` (« aucune action automatique sûre »). Le détecteur a vu un comportement inhabituel mais aucune mesure typique d'une attaque (ni débit, ni latence, ni erreurs) ne dépasse sa norme : le moteur n'agit volontairement pas, car bannir ou redémarrer sur une simple suspicion pourrait aggraver la situation.
Action : regarder le service (dashboard, Grafana), vérifier avec le smoke test. Si le service est normal, il s'agit probablement d'une fausse alerte : surveiller le score (voir « Score d'anomalie élevé au repos »). Si le service est dégradé, traiter comme une saturation ou une panne.

## Score d'anomalie élevé au repos
Symptômes : le panneau Grafana « Score d'anomalie vs seuil » reste proche de 0,70 sans attaque, ou le détecteur ouvre des incidents sans cause. Normal : entre 0,40 et 0,58 au repos.
Cause probable : le comportement de l'hôte a changé depuis l'entraînement (redémarrage du PC, autre charge, modification de la plateforme). Un redémarrage du PC a déjà suffi à déplacer la ligne de base.
Action : réentraîner le détecteur avec la session longue (README, « Entraîner le détecteur » : `tools/training_session.py`, ~2 h 12, détecteur arrêté pendant la collecte). Ne jamais lancer la collecte avec le détecteur actif : une fausse alerte bannirait le générateur de trafic lui-même.

## Contenir une compromission
Classe `compromise` : le moteur bannit la source et vérifie la disponibilité, mais ne redémarre rien, car un redémarrage détruirait les preuves et ne corrige pas la cause. Passer à l'état CONTAINED, puis analyse humaine : journaux Loki (`{service="waf"} | json`), comptes touchés, rotation des secrets (`FORCE=1 sh tools/init_secrets.sh`, puis supprimer les volumes avec `docker compose down -v` : les mots de passe changent et PostgreSQL garde l'ancien).

## Journaux (Loki)
Grafana (http://127.0.0.1:3000, utilisateur `admin`, mot de passe dans `.secrets/grafana_password`) : source Loki, requêtes utiles :
`{service="waf"} | json | action="banned"` (requêtes refusées pour ban), `{service="remediation-engine"} |= "BAN_IP"` (bannissements décidés),
`{service="ml-detector"} |= "ANOMALIE"` (alertes du détecteur). Les événements arrivent dans Loki en moins de 15 s (vérifié).
Si Loki est vide : vérifier `docker compose logs promtail` (le proxy `docker-ro` doit autoriser `NETWORKS`, sinon Promtail
reçoit un 403 et rien n'est collecté). Limite connue : après un redémarrage du PC, les journaux de la session précédente
ne sont pas tous retransmis (Loki refuse les entrées « trop anciennes » par rapport à celles déjà reçues) ; pour
l'investigation d'un incident passé, utiliser aussi `docker compose logs <service>` et `tests/rehearsals/`.

## Remettre la démonstration à zéro
`ansible-playbook ansible/reset-demo.yml` (12 s mesurées) efface les bans, l'historique d'incidents et l'état du détecteur, puis relance le smoke test.
Sans Ansible : débannir l'identité utilisée (voir « Ban ») et `docker compose restart ml-detector remediation-engine`.

## Sauvegarde et restauration
`ansible-playbook ansible/backup.yml` crée une sauvegarde PostgreSQL (dix conservées). `ansible-playbook ansible/restore.yml` restaure la plus récente après avoir coupé le trafic entrant (19 s mesurées, test de fumée compris). Les deux ont été exécutés sur Docker.

## Après un redémarrage du PC
Docker Desktop ne démarre pas tout seul : le lancer, attendre qu'il soit prêt, puis `docker compose up -d --wait --wait-timeout 240` et le smoke test. Le modèle du détecteur (`models/iforest.joblib`) est conservé : aucun réentraînement n'est nécessaire sauf si le score au repos dérive.
