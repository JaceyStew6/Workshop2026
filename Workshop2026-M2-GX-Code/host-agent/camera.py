"""Gestion de la caméra USB du PC Hôte : ouverture à la demande, arrêt garanti.

Principe de confidentialité : la caméra n'est ouverte que pendant une session d'authentification ; un
chien de garde la referme de lui-même au bout de `max_seconds` même si le service appelant tombe.
Le module ne conserve ni image ni flux : `observe()` renvoie un vecteur, jamais une image.
"""
from __future__ import annotations

import hashlib
import threading
import time
from typing import Callable, List, Optional, Protocol

import numpy as np

from face import FaceEngine, Observation


class Backend(Protocol):
    def open(self) -> None: ...
    def observe(self) -> Observation: ...
    def close(self) -> None: ...


class OpenCvBackend:
    """Vraie caméra (DirectShow sous Windows) + moteur de reconnaissance."""

    def __init__(self, index: int, engine: FaceEngine, width: int = 640, height: int = 480):
        import cv2
        self._cv2, self._index, self._engine = cv2, index, engine
        self._size = (width, height)
        self._cap = None

    def open(self) -> None:
        cv2 = self._cv2
        cap = cv2.VideoCapture(self._index, cv2.CAP_DSHOW)
        if not cap.isOpened():
            cap.release()
            cap = cv2.VideoCapture(self._index)
        if not cap.isOpened():
            cap.release()
            raise RuntimeError(f"caméra {self._index} introuvable ou occupée par une autre application")
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, self._size[0])
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, self._size[1])
        for _ in range(8):      # les premières images sont sombres le temps de l'exposition automatique
            cap.read()
        self._cap = cap

    def observe(self) -> Observation:
        if self._cap is None:
            return Observation("camera_error")
        ok, frame = self._cap.read()
        if not ok or frame is None:
            return Observation("camera_error")
        try:
            return self._engine.observe(frame)
        finally:
            del frame            # l'image n'existe que le temps de l'analyse

    def close(self) -> None:
        if self._cap is not None:
            self._cap.release()
            self._cap = None


def person_embedding(name: str, noise: float = 0.0, rng: Optional[np.random.Generator] = None) -> np.ndarray:
    """Embedding déterministe d'une « personne » fictive (tests et développement sans caméra)."""
    seed = int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], "big")
    v = np.random.default_rng(seed).normal(size=128).astype(np.float32)
    if noise:
        v = v + (rng or np.random.default_rng()).normal(scale=noise, size=128).astype(np.float32)
    return v / np.linalg.norm(v)


class FakeBackend:
    """Caméra simulée : « voit » la personne choisie via `set_person` (ou rien, ou plusieurs personnes)."""

    def __init__(self):
        self.person: Optional[str] = None
        self.reason_override: Optional[str] = None
        self.opened = False
        self._rng = np.random.default_rng(1)

    def set_person(self, name: Optional[str], reason: Optional[str] = None) -> None:
        self.person, self.reason_override = name, reason

    def open(self) -> None:
        self.opened = True

    def observe(self) -> Observation:
        if self.reason_override:
            return Observation(self.reason_override)
        if self.person is None:
            return Observation("no_face")
        return Observation("ok", person_embedding(self.person, noise=0.02, rng=self._rng), faces=1, score=0.99, size_px=180)

    def close(self) -> None:
        self.opened = False


class CameraBusy(Exception):
    pass


class CameraOff(Exception):
    pass


class CameraSession:
    """Une seule session à la fois. `on()` ouvre, `embed()` analyse, `off()` ferme ; le chien de garde ferme aussi."""

    def __init__(self, backend: Backend, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
        self._b, self._clock, self._sleep = backend, clock, sleep
        self._lock = threading.RLock()
        self._deadline: Optional[float] = None
        self._on = False
        self._timer: Optional[threading.Timer] = None
        self.opened_total = 0

    @property
    def is_on(self) -> bool:
        with self._lock:
            return self._on

    def on(self, max_seconds: float) -> None:
        with self._lock:
            if self._on:
                self._arm(max_seconds)          # déjà ouverte : on prolonge seulement le chien de garde
                return
            self._b.open()
            self._on = True
            self.opened_total += 1
            self._arm(max_seconds)

    def _arm(self, max_seconds: float) -> None:
        if self._timer:
            self._timer.cancel()
        self._deadline = self._clock() + max_seconds
        self._timer = threading.Timer(max_seconds, self.off)
        self._timer.daemon = True
        self._timer.start()

    def off(self) -> None:
        with self._lock:
            if self._timer:
                self._timer.cancel()
                self._timer = None
            if self._on:
                self._b.close()
                self._on = False
            self._deadline = None

    def embed(self, frames: int, timeout_s: float, spacing_s: float = 0.12) -> dict:
        """Collecte jusqu'à `frames` embeddings d'images distinctes, dans la limite de `timeout_s`."""
        with self._lock:
            if not self._on:
                raise CameraOff()
            end = self._clock() + timeout_s
            vectors: List[np.ndarray] = []
            seen = {"no_face": 0, "multiple_faces": 0, "too_small": 0, "camera_error": 0}
            analysed, best_score = 0, 0.0
            while len(vectors) < frames and self._clock() < end:
                obs = self._b.observe()
                analysed += 1
                if obs.reason == "ok" and obs.embedding is not None:
                    vectors.append(obs.embedding)
                    best_score = max(best_score, obs.score)
                    self._sleep(spacing_s)
                else:
                    seen[obs.reason] = seen.get(obs.reason, 0) + 1
                    self._sleep(0.05)
            reason = "ok" if len(vectors) >= frames else max(seen, key=seen.get) if any(seen.values()) else "timeout"
            if reason != "ok" and vectors:
                reason = "partial"
            return {"embeddings": [v.round(6).tolist() for v in vectors], "frames_analysed": analysed,
                    "reason": reason, "faces_score": round(best_score, 3), "counters": seen}
