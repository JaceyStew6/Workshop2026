"""Moteur de remédiation câblé pour l'exécution NATIVE (banc d'essai uniquement).

Même moteur, mêmes adaptateurs WAF et sonde que la production ; seul le contrôleur change :
ProcessController redémarre le processus uvicorn au lieu d'appeler Docker. Il n'est PAS livré dans
l'image de production (services/remediation-engine) : il exécute des commandes locales.
"""
import asyncio
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services" / "remediation-engine"))

import uvicorn  # noqa: E402

from adapters import HttpProbe, HttpWaf  # noqa: E402
from engine import Settings  # noqa: E402
from main import create_app, secret  # noqa: E402

RUN = os.environ.get("RUN", "/tmp/ra-run")


class ProcessController:
    def __init__(self, stack_script: str, services: dict):
        self.script, self.services = stack_script, services      # conteneur logique -> nom de service du script

    async def restart(self, target):
        name = self.services.get(target)
        if not name:
            return False, "cible inconnue"
        def go():
            subprocess.run(["sh", self.script, "stop", name], env={**os.environ, "RUN": RUN}, check=False, capture_output=True)
            return subprocess.run(["sh", self.script, "start", name], env={**os.environ, "RUN": RUN}, check=False, capture_output=True)
        r = await asyncio.get_running_loop().run_in_executor(None, go)
        return r.returncode == 0, f"processus {name} relancé"

    async def healthy(self, target):
        import httpx
        try:
            async with httpx.AsyncClient(timeout=1.5) as c:
                return (await c.get("http://127.0.0.1:18002/healthz")).status_code == 200
        except httpx.HTTPError:
            return False


def build():
    s = f"{RUN}/.secrets/"
    settings = Settings(
        allowed_targets={"payment-api": "payment"},
        never_ban={"192.168.137.1"},
        ban_ttl=int(os.environ.get("BAN_TTL_SECONDS", "300")), ban_min_rps=30.0,
        health_wait=float(os.environ.get("HEALTH_WAIT_SECONDS", "15")), restart_wait=40, verify_timeout=40, poll=1.5,
        max_restarts=3, restart_window=300)
    waf = HttpWaf("http://127.0.0.1:18082", open(s + "waf_admin_token").read().strip())
    probe = HttpProbe("http://127.0.0.1:18081", "synthetic-probe", open(s + "probe_password").read().strip(),
                     public_url="http://127.0.0.1:18080")
    ctl = ProcessController(str(ROOT / "tests/e2e/stack.sh"), {"payment": "payment"})
    return create_app(settings, waf, ctl, probe, open(s + "remediation_token").read().strip(),
                      audit_path=f"{RUN}/logs/remediation-audit.jsonl", monitor_interval=1.0)


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    uvicorn.run(build(), host="127.0.0.1", port=18000, log_level="warning", access_log=False)
