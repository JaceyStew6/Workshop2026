# Agent hôte — caméra USB et reconnaissance faciale

Docker Desktop (WSL2) ne sait pas transmettre une caméra USB à un conteneur Linux. La partie « caméra + IA de
reconnaissance » tourne donc **directement sur le PC Hôte**, dans un petit service Python. Les conteneurs (service
`face-gate`) l'appellent via `host.docker.internal`.

```
navigateur ──► WAF ──► face-gate (conteneur) ──► agent hôte 127.0.0.1:8095 ──► caméra USB
                              │                         (OpenCV : YuNet + SFace)
                              └──► ESP8266 (LED) interroge face-gate par le WiFi du hotspot
```

## Garanties de sécurité et de vie privée

| Garantie | Mise en œuvre |
|---|---|
| Caméra éteinte par défaut | Ouverte uniquement sur `POST /v1/camera/on`, fermée sur `/off` ; **chien de garde** : extinction automatique après `max_seconds` (5–300 s) même si face-gate tombe |
| Aucune image conservée | Chaque image est analysée en mémoire puis détruite ; seuls des vecteurs de 128 nombres (empreintes) sortent de l'agent |
| Agent non exposé | Écoute `127.0.0.1` uniquement (refus de démarrer sur une autre adresse sans `--allow-remote`), jeton secret obligatoire (`.secrets/face_agent_token`) |
| Modèles intègres | Les deux modèles ONNX sont vérifiés par SHA-256 au téléchargement et au chargement |
| Un seul visage | Plusieurs visages, visage trop petit (< 90 px) ou absent : aucune empreinte produite |

La décision (comparaison avec les empreintes enregistrées, seuil, verrouillage) est prise par **face-gate**, pas par
l'agent : l'agent ne connaît ni les utilisateurs ni les mots de passe.

## Installation (une fois)

```powershell
.\.venv\Scripts\python.exe -m pip install -r host-agent\requirements.txt
.\.venv\Scripts\python.exe host-agent\fetch_models.py
```

## Lancement

```powershell
.\host-agent\run-agent.ps1            # vraie caméra (index 0 ; -Camera 1 pour une autre)
.\host-agent\run-agent.ps1 -Fake      # caméra simulée, sans matériel (développement et tests)
```

## Régler la caméra avant la première inscription

La personne devant la caméra lance :

```powershell
cd host-agent
..\.venv\Scripts\python.exe selftest.py --seconds 6
```

Le script affiche uniquement des statistiques (images lues, visages exploitables, luminosité). Il n'enregistre ni
n'affiche aucune image.

## Anti-usurpation

Le modèle ne détecte **pas** une photo ou une vidéo présentée devant la caméra (pas de détection de vivacité).
Risque accepté et documenté dans l'analyse EBIOS ; il est compensé par le second facteur (mot de passe), le verrouillage
et la journalisation.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest host-agent\tests -q
```
