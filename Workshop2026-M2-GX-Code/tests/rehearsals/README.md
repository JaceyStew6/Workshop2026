# Répétitions de la démonstration (une seule machine, attaquant simulé)

Produites par `tools/rehearsal.py` : une attaque de 120 s, un client légitime (devis + virement chaque seconde) et
une lecture de l'incident côté moteur de remédiation, sans aucune intervention. Détecteur entraîné sur 132 minutes
de trafic (phases actives et inactives, voir `tools/training_session.py`), 7 mesures, seuil 0,70.

| N° | Attaque | Détection | Reprise | Détection → reprise | Score | Pire devis / pire virement | Virements OK après reprise | Verdict |
|---|---|---|---|---|---|---|---|---|
| 1 | 300 req/s | 11.9 s | 21.0 s | 9.1 s | 0.775 | 1059 / 1584 ms | 100% | REUSSI |
| 2 | 300 req/s | 16.6 s | 28.5 s | 11.8 s | 0.776 | 1731 / 1990 ms | 100% | REUSSI |
| 3 | 500 req/s | 13.6 s | 25.4 s | 11.8 s | 0.772 | 2104 / 1897 ms | 100% | REUSSI |

Critères (tous obligatoires) : incident `RECOVERED`, IP bannie = celle de l'attaquant (jamais la passerelle),
reprise **pendant** que l'attaque continue, au moins 95 % des virements du client légitime aboutissent après la
reprise, dégradation réellement observée avant. Le détail (échantillons seconde par seconde, incident complet,
journal du script d'attaque) est dans `run-N/`.

**Ce que ces essais ne prouvent pas** : l'attaquant est simulé par l'en-tête `X-Forwarded-For` (`--spoof-ip`) sur la
même machine que la plateforme. Ils démontrent la chaîne détection → décision → reprise → preuve par transaction,
pas la capture de la vraie adresse IP d'un second PC (à valider sur le dispositif à deux PC).
