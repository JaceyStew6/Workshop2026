"""Anti faux positifs : un score isolé ne déclenche jamais la remédiation.

Debouncer     : déclenche si K des N derniers échantillons dépassent le seuil (3 sur 4 = ~15-20 s).
IncidentGate  : un seul incident par épisode. Réarmé après `rearm_after` échantillons
                consécutifs sous le seuil, ou après `max_hold` échantillons si le
                moteur n'a jamais confirmé le retour à la normale (évite un détecteur muet à vie).
"""
from __future__ import annotations

from collections import deque


class Debouncer:
    def __init__(self, k: int = 3, n: int = 4):
        assert 1 <= k <= n
        self.k, self.window = k, deque(maxlen=n)

    def update(self, above: bool) -> bool:
        self.window.append(bool(above))
        return sum(self.window) >= self.k


class IncidentGate:
    def __init__(self, rearm_after: int = 6, max_hold: int = 120):
        self.rearm_after, self.max_hold = rearm_after, max_hold
        self.open = False
        self._calm = 0
        self._held = 0

    def should_fire(self, triggered: bool, above: bool) -> bool:
        if not self.open:
            if triggered:
                self.open, self._calm, self._held = True, 0, 0
                return True
            return False
        self._held += 1
        self._calm = 0 if above else self._calm + 1
        if self._calm >= self.rearm_after or self._held >= self.max_hold:
            self.open = False
        return False
