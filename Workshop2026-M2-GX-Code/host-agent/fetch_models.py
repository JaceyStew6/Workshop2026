"""Télécharge les deux modèles ONNX (détection YuNet, reconnaissance SFace) et vérifie leur somme de contrôle.

  python fetch_models.py

Les fichiers (≈ 39 Mo) ne sont pas versionnés dans Git. Une somme de contrôle inattendue interrompt tout :
un modèle remplacé changerait silencieusement le comportement de la reconnaissance.
"""
import sys
import urllib.request
from pathlib import Path

from face import MODELS, sha256_of

DEST = Path(__file__).parent / "models"


def main() -> None:
    DEST.mkdir(exist_ok=True)
    for name, expected, url in MODELS.values():
        path = DEST / name
        if path.exists() and sha256_of(path) == expected:
            print(f"déjà présent et conforme : {name}")
            continue
        print(f"téléchargement : {name}")
        with urllib.request.urlopen(url, timeout=180) as r:
            data = r.read()
        path.write_bytes(data)
        if sha256_of(path) != expected:
            path.unlink()
            sys.exit(f"somme de contrôle inattendue pour {name} : fichier supprimé")
        print(f"  ok ({len(data):,} octets)")


if __name__ == "__main__":
    main()
