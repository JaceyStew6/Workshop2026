"""Auto-test de la chaîne caméra + reconnaissance, À LANCER PAR LA PERSONNE DEVANT LA CAMÉRA.

  python selftest.py [--camera-index 0] [--seconds 6]

Allume la caméra quelques secondes, analyse les images et affiche des STATISTIQUES : nombre d'images lues, de
visages détectés, taille et confiance moyennes. Aucune image n'est enregistrée, affichée ni transmise ; la caméra
est éteinte à la fin. Utile pour régler la distance, la lumière et l'index de caméra avant la première inscription.
"""
import argparse
import time
from pathlib import Path

from face import FaceEngine, MODELS


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--camera-index", type=int, default=0)
    ap.add_argument("--seconds", type=float, default=6.0)
    ap.add_argument("--models", default=str(Path(__file__).parent / "models"))
    a = ap.parse_args()

    import cv2
    engine = FaceEngine(Path(a.models))
    print(f"modèles chargés et vérifiés : {', '.join(m[0] for m in MODELS.values())}")
    cap = cv2.VideoCapture(a.camera_index, cv2.CAP_DSHOW)
    if not cap.isOpened():
        raise SystemExit(f"caméra {a.camera_index} introuvable ou occupée par une autre application")
    print(f"caméra {a.camera_index} ouverte ({int(cap.get(3))}x{int(cap.get(4))}) : regardez l'objectif pendant {a.seconds:.0f} s...")
    counts, scores, sizes, read, bright = {}, [], [], 0, []
    end = time.time() + a.seconds
    try:
        while time.time() < end:
            ok, frame = cap.read()
            if not ok:
                counts["lecture_echouee"] = counts.get("lecture_echouee", 0) + 1
                continue
            read += 1
            bright.append(float(frame.mean()))
            obs = engine.observe(frame)
            del frame
            counts[obs.reason] = counts.get(obs.reason, 0) + 1
            if obs.reason == "ok":
                scores.append(obs.score)
                sizes.append(obs.size_px)
    finally:
        cap.release()
    print(f"caméra éteinte. Images lues : {read}")
    print("résultats :", counts)
    if bright:
        print(f"luminosité moyenne : {sum(bright) / len(bright):.0f}/255 ({'trop sombre' if sum(bright) / len(bright) < 60 else 'correcte'})")
    if scores:
        print(f"visage exploitable sur {len(scores)} images ; confiance moyenne {sum(scores) / len(scores):.2f} ; taille moyenne {sum(sizes) / len(sizes):.0f} px")
        print("=> OK pour l'inscription et la reconnaissance.")
    else:
        print("=> aucun visage exploitable : rapprochez-vous, éclairez le visage de face, une seule personne dans le champ.")


if __name__ == "__main__":
    main()
