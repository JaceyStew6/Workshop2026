# Runbooks opérateur

## Saturation
Symptômes : latence p95 de payment-api > 500 ms, taux de 5xx qui monte, une IP à débit anormal.
Réponse automatique : le moteur bannit la source (si > 30 req/s), attend le retour à la normale, redémarre
payment-api seulement si le service reste dégradé, puis vérifie par une transaction de contrôle.
Vérification manuelle : `python3 tools/smoke.py --base http://192.168.137.1`.
Escalade : si l'incident passe à ESCALATED, consulter le dashboard (http://127.0.0.1:8088), l'étape en échec et le journal d'audit du moteur.

## Ban
Un ban est temporaire (600 s). Lister : `GET http://waf:8082/v1/bans` avec le jeton d'administration du WAF. Débannir à la main une IP légitime : `DELETE /v1/bans/<ip>`. L'IP du PC Hôte ne peut jamais être bannie.

## Brute force
Symptômes : alerte AuthBruteForce, réponses 401 puis 429 sur `/auth/token`. Le compte visé est verrouillé 5 minutes après 5 échecs. Conséquence connue : un attaquant peut verrouiller un compte légitime (déni de service ciblé). Action : identifier la source dans les journaux WAF (`event=waf`, `status=401`), la bannir si besoin.

## Injection
Symptômes : alerte WafSignatureBlocks, requêtes 403 avec identifiants de règles 942xxx (SQL), 941xxx (XSS), 930xxx (fichiers), 932xxx (commandes). Le WAF a déjà bloqué ces requêtes. Une tentative d'injection n'est PAS une panne : on ne redémarre rien. Conserver les journaux, identifier la source, vérifier que l'API ne construit aucune requête SQL par concaténation (elle utilise des paramètres liés), escalader pour investigation.

## Escalade
Un incident ESCALATED signifie que la reprise automatique n'a pas pu être prouvée dans le délai. Étapes : 1) lire l'incident (`GET /v1/incidents/<id>` ou dashboard) ; 2) identifier l'étape de la sonde en échec (devis, connexion, paiement, relecture, grand livre) ; 3) si le grand livre est incohérent, ne PAS rouvrir le trafic : restaurer la sauvegarde (`ansible-playbook ansible/restore.yml`) ; 4) sinon redémarrer manuellement le composant fautif et relancer le smoke test.

## Contenir une compromission
Classe `compromise` : le moteur bannit la source et vérifie la disponibilité, mais ne redémarre rien, car un redémarrage détruirait les preuves et ne corrige pas la cause. Passer à l'état CONTAINED, puis analyse humaine : journaux Loki (`{service="waf"} | json`), comptes touchés, rotation des secrets (`FORCE=1 sh tools/init_secrets.sh`).

## Remettre la démonstration à zéro
`ansible-playbook ansible/reset-demo.yml` efface les bans, l'historique d'incidents et l'état du détecteur, puis relance le smoke test.

## Sauvegarde et restauration
`ansible-playbook ansible/backup.yml` crée une sauvegarde PostgreSQL (dix conservées). `ansible-playbook ansible/restore.yml` restaure la plus récente après avoir coupé le trafic entrant.
