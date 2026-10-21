"""Reconnaissance faciale légère : OpenCV, détecteur YuNet + modèle SFace (embedding de 128 dimensions).

Aucune image n'est conservée : une image est lue, analysée, puis jetée ; seul un vecteur de 128 nombres
(« embedding ») sort de ce module. Le détecteur ne dépasse pas quelques millisecondes par image sur un PC
ordinaire, sans GPU et sans compilation (pas de dlib).

Modèles (licences permissives, https://github.com/opencv/opencv_zoo) :
  * YuNet  : détection de visage, licence MIT
  * SFace  : description de visage, licence Apache 2.0
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np

MODELS = {
    "detector": ("face_detection_yunet_2023mar.onnx",
                 "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4",
                 "https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx"),
    "recognizer": ("face_recognition_sface_2021dec.onnx",
                   "0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79",
                   "https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx"),
}
MODEL_ID = "sface-2021dec"


@dataclass
class Observation:
    """Résultat de l'analyse d'une image."""
    reason: str                              # ok | no_face | multiple_faces | too_small | camera_error
    embedding: Optional[np.ndarray] = None   # 128 flottants, norme 1 ; None si l'image est rejetée
    faces: int = 0
    score: float = 0.0                       # confiance du détecteur
    size_px: int = 0                         # plus petit côté du visage détecté


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_models(models_dir: Path) -> None:
    """Refuse de démarrer avec un modèle absent ou altéré (un modèle remplacé changerait la reconnaissance)."""
    for name, expected, _ in MODELS.values():
        path = models_dir / name
        if not path.exists():
            raise FileNotFoundError(f"modèle absent : {path} (lancer python fetch_models.py)")
        if sha256_of(path) != expected:
            raise ValueError(f"somme de contrôle inattendue pour {name} : fichier altéré ou autre version")


class FaceEngine:
    def __init__(self, models_dir: Path, score_threshold: float = 0.9, min_face_px: int = 90):
        import cv2  # import tardif : les tests de l'agent n'ont pas besoin d'OpenCV
        verify_models(models_dir)
        self._cv2 = cv2
        self.min_face_px = min_face_px
        self._det = cv2.FaceDetectorYN.create(str(models_dir / MODELS["detector"][0]), "", (320, 320),
                                              score_threshold, 0.3, 5000)
        self._rec = cv2.FaceRecognizerSF.create(str(models_dir / MODELS["recognizer"][0]), "")

    def observe(self, frame_bgr: np.ndarray) -> Observation:
        h, w = frame_bgr.shape[:2]
        self._det.setInputSize((w, h))
        _, faces = self._det.detect(frame_bgr)
        if faces is None or len(faces) == 0:
            return Observation("no_face")
        if len(faces) > 1:   # plusieurs personnes devant la caméra : ambigu, on refuse plutôt que de choisir
            return Observation("multiple_faces", faces=len(faces))
        face = faces[0]
        size = int(min(face[2], face[3]))
        if size < self.min_face_px:
            return Observation("too_small", faces=1, score=float(face[-1]), size_px=size)
        aligned = self._rec.alignCrop(frame_bgr, face)
        emb = self._rec.feature(aligned).astype(np.float32).reshape(-1)
        emb /= max(float(np.linalg.norm(emb)), 1e-9)
        return Observation("ok", emb, faces=1, score=float(face[-1]), size_px=size)
