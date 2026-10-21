# Dossier et présentation : sources et régénération

Le dossier PDF et la présentation sont produits à partir de ce dépôt, pour que leurs chiffres restent alignés
sur les mesures réelles (`tests/rehearsals/`).

| Livrable | Source | Commande (depuis la racine du dépôt, `.venv` activé ou `.\.venv\Scripts\python.exe`) |
|---|---|---|
| `Workshop2026-M2-G<n>-Dossier.pdf` | `dossier/dossier.html` + `dossier/figures/` | `python dossier/build.py --out ../Workshop2026-M2-GX-Dossier.pdf` |
| `Workshop2026-M2-G<n>-Pres.pptx` | la présentation précédente, modifiée en place | `python tools/update_presentation.py --src <ancienne>.pptx --out ../Workshop2026-M2-GX-Pres.pptx` |
| Figures de latence | `tests/rehearsals/run-*/result.json` | `python tools/plot_rehearsals.py` puis copier `tests/rehearsals/latency-all.png` dans `dossier/figures/docker-repetitions.png` |

Dépendances : `pip install pymupdf python-pptx matplotlib pillow`. Le PDF est rendu par Microsoft Edge (ou Chrome)
installé sur le poste ; l'en-pied et la pagination sont ajoutés ensuite avec PyMuPDF.

## À compléter à la main avant la remise

- **Numéro et noms de l'équipe** (page de garde, annexe « Contribution de chacun » du dossier, diapositive 1) :
  le sujet exige que la contribution de chacun soit visible. Les cases sont marquées « à compléter ».
- **Chiffres** : après de nouvelles répétitions (`tools/rehearsal.py`), régénérer les figures, mettre à jour les
  tableaux de `dossier.html` (résumé, chapitre 9) ; `update_presentation.py` relit les trois `result.json` et
  refuse d'annoncer « 3/3 » si l'une des répétitions a échoué.
- **Vérifications restantes** (chapitre 10 du dossier, diapositive 10) : attaque depuis un vrai second PC, assistant
  RAG avec Ollama, vidéo de 60 s.
