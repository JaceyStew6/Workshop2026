"""Agent hôte : expose la caméra USB du PC Hôte et la reconnaissance faciale au service `face-gate`.

Pourquoi un processus natif et pas un conteneur : sous Windows, Docker Desktop (WSL2) ne donne pas accès aux
caméras USB aux conteneurs Linux. L'agent tourne donc sur le PC Hôte ; seul le conteneur `face-gate` l'appelle,
via `host.docker.internal`.

Sécurité :
  * écoute UNIQUEMENT sur 127.0.0.1 (jamais sur l'interface du point d'accès sans fil, donc inaccessible
    au PC Attaquant) ; refuse de démarrer autrement sans --allow-remote explicite ;
  * jeton porteur obligatoire (comparaison à temps constant), lu dans un fichier de secret ;
  * la caméra ne s'allume qu'à la demande et un chien de garde l'éteint seul ;
  * aucune image ne sort ni n'est écrite : seuls des vecteurs de 128 nombres sont renvoyés.

Lancement :  python agent.py --token-file ../.secrets/face_agent_token
"""
from __future__ import annotations

import argparse
import hmac
import logging
import os
import sys
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from camera import Backend, CameraOff, CameraSession, FakeBackend

log = logging.getLogger("face-agent")
VERSION = "1.0"


class CameraOn(BaseModel):
    max_seconds: int = Field(default=120, ge=5, le=300)


class EmbedRequest(BaseModel):
    frames: int = Field(default=4, ge=1, le=10)
    timeout_s: float = Field(default=12.0, ge=1.0, le=30.0)


class FakePerson(BaseModel):
    name: Optional[str] = Field(default=None, max_length=64)
    reason: Optional[str] = Field(default=None, pattern="^(no_face|multiple_faces|too_small|camera_error)$")


def create_app(backend: Backend, token: str, camera_index: int = 0) -> FastAPI:
    if len(token) < 16:
        raise ValueError("jeton trop court (16 caractères minimum)")
    session = CameraSession(backend)
    app = FastAPI(title="face-agent", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.session = session

    def auth(authorization: Optional[str] = Header(default=None)) -> None:
        given = authorization[7:] if authorization and authorization.lower().startswith("bearer ") else ""
        if not hmac.compare_digest(given.encode(), token.encode()):
            raise HTTPException(401, "jeton invalide")

    @app.get("/v1/health", dependencies=[Depends(auth)])
    def health():
        return {"status": "ok", "version": VERSION, "camera_index": camera_index, "camera_on": session.is_on,
                "backend": type(backend).__name__, "opened_total": session.opened_total}

    @app.post("/v1/camera/on", dependencies=[Depends(auth)])
    def camera_on(req: CameraOn):
        try:
            session.on(req.max_seconds)
        except RuntimeError as exc:
            log.error("ouverture de la caméra impossible : %s", exc)
            raise HTTPException(503, str(exc))
        return {"camera_on": True, "auto_off_after_s": req.max_seconds}

    @app.post("/v1/camera/embed", dependencies=[Depends(auth)])
    def camera_embed(req: EmbedRequest):
        try:
            return session.embed(req.frames, req.timeout_s)
        except CameraOff:
            raise HTTPException(409, "caméra éteinte : appeler /v1/camera/on d'abord")

    @app.post("/v1/camera/off", dependencies=[Depends(auth)])
    def camera_off():
        session.off()
        return {"camera_on": False}

    if isinstance(backend, FakeBackend):      # uniquement en mode simulé (tests, développement sans caméra)
        @app.post("/v1/fake/person", dependencies=[Depends(auth)])
        def fake_person(req: FakePerson):
            backend.set_person(req.name, req.reason)
            return {"person": req.name, "reason": req.reason}

    return app


def build_backend(args) -> Backend:
    if args.fake or os.environ.get("FACE_AGENT_FAKE") == "1":
        log.warning("MODE SIMULÉ : aucune caméra ni reconnaissance réelle (développement uniquement)")
        return FakeBackend()
    from camera import OpenCvBackend
    from face import FaceEngine
    return OpenCvBackend(args.camera_index, FaceEngine(Path(args.models), min_face_px=args.min_face_px))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8095)
    ap.add_argument("--token-file", default=os.environ.get("FACE_AGENT_TOKEN_FILE", ""))
    ap.add_argument("--camera-index", type=int, default=int(os.environ.get("FACE_AGENT_CAMERA", "0")))
    ap.add_argument("--models", default=str(Path(__file__).parent / "models"))
    ap.add_argument("--min-face-px", type=int, default=90)
    ap.add_argument("--fake", action="store_true", help="caméra simulée (développement)")
    ap.add_argument("--allow-remote", action="store_true", help="autoriser une adresse d'écoute autre que 127.0.0.1")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format='{"ts":"%(asctime)s","svc":"face-agent","lvl":"%(levelname)s","msg":"%(message)s"}')

    if args.host not in ("127.0.0.1", "localhost", "::1") and not args.allow_remote:
        sys.exit("REFUS : l'agent n'écoute que sur 127.0.0.1 (le conteneur l'atteint via host.docker.internal). "
                 "Ne l'exposez pas sur le réseau du point d'accès : voir README du dossier host-agent.")
    token = Path(args.token_file).read_text().strip() if args.token_file else os.environ.get("FACE_AGENT_TOKEN", "")
    if not token:
        sys.exit("jeton absent : --token-file <fichier> ou variable FACE_AGENT_TOKEN")

    import uvicorn
    uvicorn.run(create_app(build_backend(args), token, args.camera_index), host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
