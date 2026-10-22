"""face-gate : cœur de la décision d'accès biométrique (sans dépendance à FastAPI, donc testable seul).

Parcours imposé par la consigne : identifiant -> caméra -> reconnaissance -> mot de passe -> accès.

  identify(user)   caméra ON, analyse de quelques images, comparaison aux empreintes chiffrées de l'utilisateur
      reconnu      LED verte clignotante jusqu'à la saisie du mot de passe ; un TICKET signé (usage unique) est
                   conservé CÔTÉ SERVEUR, le navigateur ne le voit jamais
      non reconnu  LED rouge fixe 30 s, puis caméra OFF et identifiant à ressaisir ; 2 échecs de suite => blocage 5 min
  password(...)    face-gate relaie le mot de passe à auth-service AVEC le ticket
      correct      LED verte fixe 30 s puis éteinte, caméra OFF, jeton d'accès remis
      incorrect    LED rouge clignotante 10 fois puis éteinte, caméra OFF, identification à recommencer

Invariants de sécurité (testés) : la caméra n'est jamais allumée sans session, une seule session à la fois (une seule
caméra), jamais d'image conservée, échec fermé si l'agent caméra est indisponible, LED éteinte par défaut.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

import jwt
import numpy as np

log = logging.getLogger("gate")

PATTERNS = ("off", "green_blink", "green_solid", "red_blink", "red_solid")
# Comptes machine : seuls à se connecter sans visage. Tout autre compte (humain) doit passer par la caméra.
MACHINE_ROLES = {"probe", "automation"}


def needs_face(info: dict) -> bool:
    """Visage exigé pour les utilisateurs du portail ; pas pour les comptes machine ni pour les rôles d'administration."""
    return info["role"] not in MACHINE_ROLES and "backoffice:access" not in info.get("perms", [])


@dataclass
class Config:
    threshold: float = 0.40          # similarité cosinus minimale (SFace : 0,363 recommandé par OpenCV ; marge ajoutée)
    frames: int = 5                  # images analysées par tentative
    min_votes: int = 3               # images qui doivent concorder
    scan_timeout_s: float = 8.0
    session_ttl_s: float = 120.0     # délai pour saisir le mot de passe après reconnaissance
    ticket_ttl_s: float = 120.0
    hold_denied_s: float = 30.0      # LED rouge fixe, caméra ON, après un visage non reconnu
    green_solid_s: float = 30.0      # LED verte fixe après connexion réussie
    red_blink_s: float = 10.0        # 10 clignotements d'1 s après un mot de passe erroné
    lock_after: int = 2              # échecs consécutifs avant blocage (1 essai + 1 nouvelle tentative)
    block_s: float = 300.0
    ip_limit: int = 10               # démarrages de caméra par IP et par fenêtre
    ip_window_s: float = 300.0
    enroll_frames: int = 8
    enroll_min_good: int = 6
    enroll_consistency: float = 0.50  # similarité minimale entre les images d'une inscription (même personne)
    enroll_timeout_s: float = 25.0
    camera_margin_s: float = 40.0


class GateError(Exception):
    def __init__(self, status: int, code: str, message: str, **extra):
        super().__init__(message)
        self.status, self.code, self.message, self.extra = status, code, message, extra


class AuthRejected(Exception):
    def __init__(self, status: int):
        self.status = status


class AuthUnavailable(Exception):
    pass


class AgentError(Exception):
    pass


class Agent(Protocol):
    def camera_on(self, max_seconds: int) -> None: ...
    def embed(self, frames: int, timeout_s: float) -> dict: ...
    def camera_off(self) -> None: ...
    def health(self) -> dict: ...


class AuthClient(Protocol):
    def login(self, username: str, password: str, ticket: str, ip: str) -> dict: ...


class Store(Protocol):
    def user_info(self, username: str) -> Optional[dict]: ...
    def templates(self, username: str) -> list[np.ndarray]: ...
    def list_templates(self, username: Optional[str] = None) -> list[dict]: ...
    def add_template(self, username: str, label: str, vector: np.ndarray, samples: int, created_by: str) -> int: ...
    def delete_template(self, template_id: int) -> Optional[str]: ...
    def count_templates(self, username: str) -> int: ...
    def set_face_required(self, username: str, value: bool) -> None: ...
    def audit(self, actor: str, action: str, target: str = "", detail: Optional[dict] = None, ip: str = "") -> None: ...


# --------------------------------------------------------------------------- voyant
class Led:
    """Source de vérité du voyant. Le firmware interroge `read()` environ chaque seconde et reproduit le motif
    localement ; passé `remaining_ms`, le voyant s'éteint tout seul (y compris si le serveur ne répond plus)."""

    def __init__(self, clock: Callable[[], float]):
        self._clock, self._lock = clock, threading.Lock()
        self._seq, self._pattern, self._until = 0, "off", 0.0

    def set(self, pattern: str, duration_s: float = 0.0) -> None:
        if pattern not in PATTERNS:
            raise ValueError(pattern)
        with self._lock:
            self._seq += 1
            self._pattern = pattern
            self._until = self._clock() + duration_s if pattern != "off" else 0.0

    def read(self) -> dict:
        with self._lock:
            if self._pattern != "off" and self._clock() >= self._until:
                self._seq += 1
                self._pattern, self._until = "off", 0.0
            remaining = max(0, int((self._until - self._clock()) * 1000)) if self._pattern != "off" else 0
            return {"seq": self._seq, "pattern": self._pattern, "remaining_ms": remaining}


# --------------------------------------------------------------------------- verrouillage
class Lockout:
    """N échecs consécutifs => blocage de `block_s` ; le compteur repart de zéro ensuite (blocage répétable)."""

    def __init__(self, clock, max_fails: int, block_s: float, cap: int = 5000):
        self._clock, self._max, self._block, self._cap = clock, max_fails, block_s, cap
        self._count: dict[str, int] = {}
        self._until: dict[str, float] = {}
        self._lock = threading.Lock()

    def blocked_for(self, key: str) -> int:
        with self._lock:
            until = self._until.get(key, 0.0)
            left = until - self._clock()
            if left <= 0:
                self._until.pop(key, None)
                return 0
            return int(left) + 1

    def fail(self, key: str) -> tuple[int, int]:
        """Retourne (essais restants, secondes de blocage si le seuil vient d'être atteint)."""
        with self._lock:
            if len(self._count) + len(self._until) > self._cap:     # borne la mémoire (identifiants inventés)
                now = self._clock()
                self._until = {k: v for k, v in self._until.items() if v > now}
                self._count = {k: v for k, v in self._count.items() if k in self._until}
            n = self._count.get(key, 0) + 1
            if n >= self._max:
                self._count.pop(key, None)
                self._until[key] = self._clock() + self._block
                return 0, int(self._block)
            self._count[key] = n
            return self._max - n, 0

    def success(self, key: str) -> None:
        with self._lock:
            self._count.pop(key, None)


class RateWindow:
    def __init__(self, clock, limit: int, window_s: float, cap: int = 5000):
        self._clock, self._limit, self._window, self._cap = clock, limit, window_s, cap
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        with self._lock:
            now = self._clock()
            if len(self._hits) > self._cap:
                self._hits = {k: [t for t in v if now - t < self._window] for k, v in self._hits.items()}
                self._hits = {k: v for k, v in self._hits.items() if v}
            hits = [t for t in self._hits.get(key, []) if now - t < self._window]
            if len(hits) >= self._limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True


# --------------------------------------------------------------------------- sessions
@dataclass
class Session:
    id: str
    username: str
    ip: str
    state: str = "scanning"          # scanning | awaiting_password | verifying | denied | holding | error | closed
    created: float = 0.0
    deadline: float = 0.0            # fin de la phase « mot de passe »
    hold_until: float = 0.0          # fin de la phase de maintien (LED rouge) -> caméra OFF
    reason: str = ""
    attempts_left: int = 0
    blocked_s: int = 0
    ticket: str = ""
    best: float = 0.0


@dataclass
class EnrollJob:
    id: str
    username: str
    label: str
    actor: str
    state: str = "running"           # running | done | failed
    reason: str = ""
    captured: int = 0
    template_id: Optional[int] = None


class FaceGate:
    def __init__(self, store: Store, agent: Agent, auth: AuthClient, ticket_secret: str, cfg: Optional[Config] = None,
                 clock: Callable[[], float] = time.monotonic, spawn: Optional[Callable[[Callable[[], None]], None]] = None):
        self.store, self.agent, self.auth, self.cfg, self.clock = store, agent, auth, cfg or Config(), clock
        self._ticket_secret = ticket_secret
        self.led = Led(clock)
        self.lockout = Lockout(clock, self.cfg.lock_after, self.cfg.block_s)
        self.ip_rate = RateWindow(clock, self.cfg.ip_limit, self.cfg.ip_window_s)
        self._lock = threading.RLock()
        self._session: Optional[Session] = None
        self._finished: dict[str, dict] = {}
        self._job: Optional[EnrollJob] = None
        self._jobs: dict[str, EnrollJob] = {}
        self._spawn = spawn or (lambda fn: threading.Thread(target=fn, daemon=True).start())
        self.device_seen: float = 0.0
        self.device_ip: str = ""
        self.events: list[tuple[str, str]] = []        # derniers (événement, issue), utile aux tests
        self.on_event: Optional[Callable[[str, str], None]] = None   # branché sur les métriques par api.py
        self.camera_is_on = False

    # ------------------------------------------------------------------ utilitaires internes
    def _event(self, name: str, result: str) -> None:
        self.events.append((name, result))
        del self.events[:-200]
        if self.on_event:
            self.on_event(name, result)

    def _camera_off(self) -> None:
        self.camera_is_on = False
        try:
            self.agent.camera_off()
        except Exception as exc:                       # le chien de garde de l'agent éteindra de toute façon
            log.warning("extinction caméra: %s", exc)

    def _close(self, s: Session, final: str) -> None:
        """Termine la session, éteint la caméra, mémorise l'état final pour l'interface."""
        self._camera_off()
        s.state = "closed"
        self._finished[s.id] = {"state": "closed", "final": final, "reason": s.reason, "attempts_left": s.attempts_left,
                                "blocked_s": s.blocked_s, "at": self.clock()}
        if len(self._finished) > 50:
            for k in sorted(self._finished, key=lambda k: self._finished[k]["at"])[:25]:
                del self._finished[k]
        if self._session is s:
            self._session = None

    def tick(self) -> None:
        """Échéances : maintien terminé, délai du mot de passe dépassé. Appelé par le réveil périodique et à chaque requête."""
        with self._lock:
            s, now = self._session, self.clock()
            if s is None:
                return
            if s.state in ("denied", "holding") and now >= s.hold_until:
                self._close(s, s.state)
            elif s.state == "awaiting_password" and now >= s.deadline:
                s.reason = "timeout"
                self.led.set("off")
                self._event("session", "timeout")
                self._close(s, "timeout")

    # ------------------------------------------------------------------ identification
    def identify(self, username: str, ip: str) -> dict:
        self.tick()
        left = self.lockout.blocked_for(username)
        if left:
            self._event("identify", "blocked")
            raise GateError(429, "blocked", "Trop d'échecs : identification bloquée pour cet identifiant.", blocked_s=left)
        info = self.store.user_info(username)
        if info and info["active"] and not needs_face(info):
            return {"face_required": False}      # compte machine ou d'administration : mot de passe seul
        if not self.ip_rate.allow(ip):
            self._event("identify", "ip_limited")
            raise GateError(429, "ip_limited", "Trop de tentatives depuis ce poste, patientez quelques minutes.")
        with self._lock:
            if self._session is not None or self._job is not None:
                self._event("identify", "busy")
                raise GateError(423, "busy", "La caméra est utilisée par une autre identification. Patientez.",
                                retry_s=int(max(1, (self._session.hold_until - self.clock()) if self._session else 10)))
            s = Session(id=uuid.uuid4().hex, username=username, ip=ip, created=self.clock())
            self._session = s
        self.led.set("off")
        self._spawn(lambda: self._scan(s))
        return {"face_required": True, "session_id": s.id, "state": "scanning"}

    def _decide(self, username: str, vectors: list[list[float]]) -> tuple[bool, float, int]:
        info = self.store.user_info(username)
        templates = self.store.templates(username) if info and info["active"] else []
        if not templates or len(vectors) < self.cfg.min_votes:
            return False, 0.0, 0
        votes, best = 0, 0.0
        for v in vectors:
            vec = np.asarray(v, dtype=np.float32)
            vec = vec / (np.linalg.norm(vec) or 1.0)
            score = max(float(np.dot(vec, t)) for t in templates)
            best = max(best, score)
            votes += score >= self.cfg.threshold
        return votes >= self.cfg.min_votes, best, votes

    def _scan(self, s: Session) -> None:
        try:
            self.agent.camera_on(int(self.cfg.session_ttl_s + self.cfg.camera_margin_s))
            self.camera_is_on = True
            res = self.agent.embed(self.cfg.frames, self.cfg.scan_timeout_s)
        except Exception as exc:
            log.error("agent caméra indisponible: %s", exc)
            with self._lock:
                if self._session is s:
                    s.state, s.reason = "error", "agent_unavailable"
                    self.led.set("off")
                    self._event("face", "agent_error")
                    self._close(s, "error")
            return
        vectors = res.get("embeddings", [])
        recognised, best, votes = self._decide(s.username, vectors)
        with self._lock:
            if self._session is not s or s.state != "scanning":
                return                                   # annulée entre-temps
            s.best = best
            if recognised:
                self.lockout.success(s.username)            # visage reconnu : la série d'échecs de reconnaissance est close
                now = time.time()
                s.ticket = jwt.encode({"iss": "face-gate", "aud": "auth-service", "sub": s.username, "jti": uuid.uuid4().hex,
                                       "iat": int(now), "exp": int(now + self.cfg.ticket_ttl_s)}, self._ticket_secret, algorithm="HS256")
                s.state, s.deadline = "awaiting_password", self.clock() + self.cfg.session_ttl_s
                self.led.set("green_blink", self.cfg.session_ttl_s)
                self._event("face", "recognised")
                self.store.audit("face-gate", "face.recognised", s.username, {"score": round(best, 3), "votes": votes}, s.ip)
                log.info('{"event":"face_auth","result":"recognised","user":"%s","score":%.3f,"ip":"%s"}', s.username, best, s.ip)
            else:
                s.reason = res.get("reason", "ok") if len(vectors) < self.cfg.min_votes else "not_recognised"
                s.attempts_left, s.blocked_s = self.lockout.fail(s.username)
                s.state, s.hold_until = "denied", self.clock() + self.cfg.hold_denied_s
                self.led.set("red_solid", self.cfg.hold_denied_s)
                self._event("face", "blocked" if s.blocked_s else "denied")
                self.store.audit("face-gate", "face.denied", s.username,
                                 {"reason": s.reason, "score": round(best, 3), "attempts_left": s.attempts_left,
                                  "blocked_s": s.blocked_s}, s.ip)
                log.warning('{"event":"face_auth","result":"denied","user":"%s","reason":"%s","score":%.3f,"ip":"%s"}',
                            s.username, s.reason, best, s.ip)

    def status(self, session_id: str) -> dict:
        self.tick()
        with self._lock:
            s = self._session
            if s is None or s.id != session_id:
                fin = self._finished.get(session_id)
                if not fin:
                    raise GateError(404, "unknown_session", "Session inconnue ou expirée.")
                return {"state": "closed", "final": fin["final"], "reason": fin["reason"],
                        "attempts_left": fin["attempts_left"], "blocked_s": fin["blocked_s"], "led": self.led.read()}
            out = {"state": s.state, "reason": s.reason, "attempts_left": s.attempts_left, "blocked_s": s.blocked_s,
                   "led": self.led.read(), "camera": self.camera_is_on}
            if s.state in ("denied", "holding"):
                out["retry_in_s"] = max(0, int(s.hold_until - self.clock()) + 1)
            if s.state == "awaiting_password":
                out["expires_in_s"] = max(0, int(s.deadline - self.clock()))
            return out

    def cancel(self, session_id: str) -> dict:
        with self._lock:
            s = self._session
            if s is None or s.id != session_id:
                return {"state": "closed"}
            if s.state in ("denied", "holding"):
                raise GateError(409, "hold", "Patientez : la temporisation de sécurité est en cours.")
            s.reason = "cancelled"
            self.led.set("off")
            self._event("session", "cancelled")
            self._close(s, "cancelled")
            return {"state": "closed"}

    # ------------------------------------------------------------------ mot de passe
    def password(self, session_id: str, password: str, ip: str) -> dict:
        self.tick()
        with self._lock:
            s = self._session
            if s is None or s.id != session_id:
                raise GateError(404, "unknown_session", "Session inconnue ou expirée : recommencez l'identification.")
            if s.state != "awaiting_password":
                raise GateError(409, "wrong_state", "Le visage n'est pas (ou plus) reconnu pour cette session.", state=s.state)
            s.state = "verifying"
            ticket, username = s.ticket, s.username
        try:
            token = self.auth.login(username, password, ticket, ip)
        except AuthUnavailable:
            with self._lock:
                if self._session is s and s.state == "verifying":
                    s.state = "awaiting_password"
            raise GateError(503, "auth_unavailable", "Service d'authentification indisponible, réessayez.")
        except AuthRejected as exc:
            with self._lock:
                # Les échecs de mot de passe ne comptent PAS dans le blocage facial (la consigne vise la reconnaissance) :
                # ils sont limités par auth-service (5 échecs / 5 min par compte), et chaque essai exige un nouveau scan.
                s.reason = "bad_password" if exc.status in (401, 403) else "locked"
                s.state, s.hold_until = "holding", self.clock() + self.cfg.red_blink_s
                self.led.set("red_blink", self.cfg.red_blink_s)
                self._camera_off()
                self._event("password", "failed")
                self.store.audit("face-gate", "password.failed", username, {"status": exc.status}, s.ip)
                log.warning('{"event":"face_auth","result":"password_failed","user":"%s","ip":"%s"}', username, s.ip)
            raise GateError(401, "bad_password", "Mot de passe incorrect : l'identification est à recommencer.",
                            restart=True, retry_in_s=int(self.cfg.red_blink_s))
        with self._lock:
            self.lockout.success(username)
            self.led.set("green_solid", self.cfg.green_solid_s)
            self._event("password", "ok")
            self.store.audit("face-gate", "login.success", username, {"score": round(s.best, 3)}, s.ip)
            log.info('{"event":"face_auth","result":"login_ok","user":"%s","ip":"%s"}', username, s.ip)
            self._close(s, "success")
        return token

    # ------------------------------------------------------------------ gestion des visages (back-office)
    def start_enroll(self, username: str, label: str, actor: str, ip: str) -> dict:
        self.tick()
        info = self.store.user_info(username)
        if not info or not info["active"]:
            raise GateError(404, "unknown_user", "Utilisateur introuvable ou désactivé.")
        with self._lock:
            if self._session is not None or self._job is not None:
                raise GateError(423, "busy", "La caméra est occupée. Patientez.")
            job = EnrollJob(id=uuid.uuid4().hex, username=username, label=label[:60] or "visage", actor=actor)
            self._job, self._jobs[job.id] = job, job
            if len(self._jobs) > 20:
                self._jobs.pop(next(iter(self._jobs)))
        self.led.set("off")
        self._spawn(lambda: self._enroll(job, ip))
        return {"job_id": job.id, "state": "running"}

    def _enroll(self, job: EnrollJob, ip: str) -> None:
        cfg = self.cfg
        try:
            self.agent.camera_on(int(cfg.enroll_timeout_s + cfg.camera_margin_s))
            self.camera_is_on = True
            res = self.agent.embed(cfg.enroll_frames, cfg.enroll_timeout_s)
            vectors = [np.asarray(v, dtype=np.float32) for v in res.get("embeddings", [])]
            job.captured = len(vectors)
            if len(vectors) < cfg.enroll_min_good:
                job.state, job.reason = "failed", res.get("reason", "partial")
                return
            vectors = [v / (np.linalg.norm(v) or 1.0) for v in vectors]
            mean = np.mean(vectors, axis=0)
            mean = mean / (np.linalg.norm(mean) or 1.0)
            gram = np.asarray(vectors) @ np.asarray(vectors).T       # similarités deux à deux : une seule personne, immobile
            if float(gram[~np.eye(len(vectors), dtype=bool)].min()) < cfg.enroll_consistency:
                job.state, job.reason = "failed", "inconsistent"     # plusieurs personnes / mouvement : on refuse
                return
            job.template_id = self.store.add_template(job.username, job.label, mean.astype(np.float32), len(vectors), job.actor)
            self.store.audit(job.actor, "face.enroll", job.username, {"template": job.template_id, "samples": len(vectors)}, ip)
            self._event("enroll", "ok")
            job.state = "done"
        except Exception as exc:
            log.error("inscription: %s", exc)
            job.state, job.reason = "failed", "agent_unavailable"
            self._event("enroll", "error")
        finally:
            with self._lock:
                self._camera_off()
                if self._job is job:
                    self._job = None

    def enroll_status(self, job_id: str) -> dict:
        job = self._jobs.get(job_id)
        if not job:
            raise GateError(404, "unknown_job", "Inscription inconnue.")
        return {"state": job.state, "reason": job.reason, "captured": job.captured, "template_id": job.template_id}

    def delete_face(self, template_id: int, actor: str, ip: str) -> dict:
        rows = [t for t in self.store.list_templates() if t["id"] == template_id]
        if not rows:
            raise GateError(404, "unknown_template", "Empreinte introuvable.")
        username = rows[0]["username"]
        info = self.store.user_info(username)
        if info and needs_face(info) and self.store.count_templates(username) <= 1:
            raise GateError(409, "last_template", "Dernière empreinte de ce compte : le supprimer l'empêcherait de se connecter. "
                                                  "Inscrivez d'abord la nouvelle empreinte, puis supprimez l'ancienne.")
        self.store.delete_template(template_id)
        self.store.audit(actor, "face.delete", username, {"template": template_id}, ip)
        return {"deleted": template_id}

    # ------------------------------------------------------------------ voyant / dispositif
    def device_poll(self, ip: str) -> dict:
        self.tick()
        self.device_seen, self.device_ip = time.time(), ip
        return self.led.read()

    def device_status(self) -> dict:
        self.tick()
        try:
            agent = {"ok": True, **self.agent.health()}
        except Exception:
            agent = {"ok": False}
        seen = self.device_seen
        return {"led": self.led.read(), "agent": agent,
                "device": {"online": bool(seen) and time.time() - seen < 10, "last_seen_s": int(time.time() - seen) if seen else None,
                           "ip": self.device_ip},
                "busy": "session" if self._session else "enroll" if self._job else ""}

    def led_test(self, pattern: str, seconds: float, actor: str, ip: str) -> dict:
        if pattern not in PATTERNS:
            raise GateError(422, "bad_pattern", "Motif inconnu.")
        with self._lock:
            if self._session is not None or self._job is not None:
                raise GateError(423, "busy", "Une identification est en cours : test impossible.")
            self.led.set(pattern, min(max(seconds, 1.0), 15.0))
        self.store.audit(actor, "led.test", pattern, {}, ip)
        return self.led.read()

    def shutdown_camera(self) -> None:
        """Arrêt d'urgence (arrêt du service) : caméra OFF, voyant éteint."""
        with self._lock:
            self._session = None
            self._job = None
            self.led.set("off")
            self._camera_off()
