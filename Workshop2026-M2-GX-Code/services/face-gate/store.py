"""Accès aux données de face-gate : empreintes faciales chiffrées (AES-GCM) et journal d'audit.

Une empreinte est un vecteur de 128 nombres (jamais une image). Elle est chiffrée avant d'être écrite : un vol de la
base seule ne donne pas les empreintes (la clé `face_template_key` est un secret Docker distinct du mot de passe SQL).
Le nom d'utilisateur sert de donnée authentifiée associée : une empreinte recopiée vers un autre compte est rejetée.
"""
from __future__ import annotations

import json
import os
from typing import Optional

import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def seal(key: bytes, username: str, vector: np.ndarray) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, np.asarray(vector, dtype=np.float32).tobytes(), username.encode())


def unseal(key: bytes, username: str, nonce: bytes, ciphertext: bytes) -> np.ndarray:
    return np.frombuffer(AESGCM(key).decrypt(bytes(nonce), bytes(ciphertext), username.encode()), dtype=np.float32).copy()


def load_key(raw: str) -> bytes:
    """La clé est stockée en texte (base64 URL-safe de 32 octets) dans le secret Docker."""
    import base64
    key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    if len(key) != 32:
        raise ValueError("face_template_key doit contenir 32 octets (base64)")
    return key


class PgStore:
    def __init__(self, pool, key: bytes):
        self.pool, self.key = pool, key

    def user_info(self, username: str) -> Optional[dict]:
        with self.pool.connection() as conn:
            row = conn.execute("SELECT username, role, face_required, active FROM users WHERE username=%s",
                               (username,)).fetchone()
        return {"username": row[0], "role": row[1], "face_required": row[2], "active": row[3]} if row else None

    def templates(self, username: str) -> list[np.ndarray]:
        with self.pool.connection() as conn:
            rows = conn.execute("SELECT nonce, ciphertext FROM face_templates WHERE username=%s", (username,)).fetchall()
        return [unseal(self.key, username, r[0], r[1]) for r in rows]

    def list_templates(self, username: Optional[str] = None) -> list[dict]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                "SELECT id, username, label, samples, created_by, created_at FROM face_templates "
                "WHERE (%s::text IS NULL OR username=%s) ORDER BY id", (username, username)).fetchall()
        return [{"id": r[0], "username": r[1], "label": r[2], "samples": r[3], "created_by": r[4],
                 "created_at": r[5].isoformat()} for r in rows]

    def add_template(self, username: str, label: str, vector: np.ndarray, samples: int, created_by: str) -> int:
        nonce, ct = seal(self.key, username, vector)
        with self.pool.connection() as conn:
            return conn.execute("INSERT INTO face_templates (username,label,nonce,ciphertext,samples,created_by) "
                                "VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
                                (username, label, nonce, ct, samples, created_by)).fetchone()[0]

    def delete_template(self, template_id: int) -> Optional[str]:
        with self.pool.connection() as conn:
            row = conn.execute("DELETE FROM face_templates WHERE id=%s RETURNING username", (template_id,)).fetchone()
        return row[0] if row else None

    def count_templates(self, username: str) -> int:
        with self.pool.connection() as conn:
            return conn.execute("SELECT count(*) FROM face_templates WHERE username=%s", (username,)).fetchone()[0]

    def set_face_required(self, username: str, value: bool) -> None:
        with self.pool.connection() as conn:
            conn.execute("UPDATE users SET face_required=%s WHERE username=%s", (value, username))

    def audit(self, actor: str, action: str, target: str = "", detail: Optional[dict] = None, ip: str = "") -> None:
        try:
            with self.pool.connection() as conn:
                conn.execute("INSERT INTO audit_log (actor,action,target,detail,ip) VALUES (%s,%s,%s,%s::jsonb,%s)",
                             (actor, action, target, json.dumps(detail or {}), ip))
        except Exception:                      # l'audit ne doit jamais empêcher (ni autoriser) une authentification
            pass


class MemoryStore:
    """Implémentation en mémoire (tests et démonstration sans base)."""

    def __init__(self, key: Optional[bytes] = None):
        self.key = key or os.urandom(32)
        self.users: dict[str, dict] = {}
        self._tpl: dict[int, dict] = {}
        self._next = 1
        self.audit_log: list[dict] = []

    def add_user(self, username: str, role: str = "admin", face_required: bool = True, active: bool = True) -> None:
        self.users[username] = {"username": username, "role": role, "face_required": face_required, "active": active}

    def user_info(self, username):
        u = self.users.get(username)
        return dict(u) if u else None

    def templates(self, username):
        return [unseal(self.key, username, t["nonce"], t["ct"]) for t in self._tpl.values() if t["username"] == username]

    def list_templates(self, username=None):
        return [{"id": i, "username": t["username"], "label": t["label"], "samples": t["samples"], "created_by": t["by"],
                 "created_at": "t"} for i, t in self._tpl.items() if username in (None, t["username"])]

    def add_template(self, username, label, vector, samples, created_by):
        i, self._next = self._next, self._next + 1
        nonce, ct = seal(self.key, username, vector)
        self._tpl[i] = {"username": username, "label": label, "nonce": nonce, "ct": ct, "samples": samples, "by": created_by}
        return i

    def delete_template(self, template_id):
        t = self._tpl.pop(template_id, None)
        return t["username"] if t else None

    def count_templates(self, username):
        return sum(1 for t in self._tpl.values() if t["username"] == username)

    def set_face_required(self, username, value):
        self.users[username]["face_required"] = value

    def audit(self, actor, action, target="", detail=None, ip=""):
        self.audit_log.append({"actor": actor, "action": action, "target": target, "detail": detail or {}, "ip": ip})
