"""Point d'entrée de face-gate : câblage depuis l'environnement (secrets lus dans des fichiers)."""
import os

from psycopg_pool import ConnectionPool

from api import create_app
from clients import HttpAgent, HttpAuth
from gate import Config, FaceGate
from store import PgStore, load_key


def secret(env: str) -> str:
    path = os.environ.get(env)
    return open(path).read().strip() if path and os.path.exists(path) else ""


_db = dict(host=os.environ.get("DB_HOST", "localhost"), port=os.environ.get("DB_PORT", "5432"),
           dbname=os.environ.get("DB_NAME", "payments"), user=os.environ.get("DB_USER", "gate_svc"),
           password=secret("DB_PASSWORD_FILE"))
pool = ConnectionPool(conninfo=" ".join(f"{k}={v}" for k, v in _db.items() if v), min_size=1, max_size=4, timeout=2.0, open=True)

_cfg = Config(threshold=float(os.environ.get("FACE_THRESHOLD", "0.40")),
              min_votes=int(os.environ.get("FACE_MIN_VOTES", "3")))
_gate = FaceGate(PgStore(pool, load_key(secret("FACE_TEMPLATE_KEY_FILE"))),
                 HttpAgent(os.environ.get("AGENT_URL", "http://host.docker.internal:8095"), secret("FACE_AGENT_TOKEN_FILE")),
                 HttpAuth(os.environ.get("AUTH_URL", "http://auth-service:8000")),
                 secret("FACE_TICKET_SECRET_FILE"), _cfg)
app = create_app(_gate, secret("JWT_SECRET_FILE"), secret("DEVICE_TOKEN_FILE"))
