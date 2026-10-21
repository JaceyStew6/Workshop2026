"""Catalogue unique des secrets de la plateforme (nom -> type, longueur). Bibliothèque standard uniquement.

  python tools/secrets_catalog.py ensure          crée dans .secrets/ les secrets MANQUANTS (flux sans SOPS)
  python tools/secrets_catalog.py missing-json    lit un JSON {nom: valeur} sur stdin, écrit sur stdout le JSON
                                                  COMPLÉTÉ des secrets manquants (flux SOPS : voir init_secrets.sh)

Un secret existant n'est jamais modifié : ajouter une fonctionnalité ne change aucun mot de passe en place.
"""
import base64
import json
import os
import secrets
import sys
from pathlib import Path

SPEC = {
    "db_password": ("urlsafe", 24),
    "jwt_secret": ("urlsafe", 48),
    "remediation_token": ("urlsafe", 24),
    "waf_admin_token": ("urlsafe", 24),
    "probe_password": ("urlsafe", 24),
    "demo_password": ("urlsafe", 16),
    "grafana_password": ("urlsafe", 16),
    # --- Consigne additionnelle 1 : reconnaissance faciale, voyant ESP8266, habilitations
    "face_ticket_secret": ("urlsafe", 48),     # signe le ticket facial (face-gate -> auth-service)
    "face_template_key": ("aes256", 32),       # chiffre les empreintes faciales en base (AES-256-GCM)
    "face_agent_token": ("urlsafe", 32),       # jeton entre face-gate et l'agent caméra du PC Hôte
    "device_token": ("urlsafe", 32),           # jeton de l'ESP8266 (compilé dans son firmware)
    "admin_password": ("urlsafe", 18),         # compte « admin » du back-office
    "operator_password": ("urlsafe", 18),      # compte « operator » du back-office
}


def generate(kind: str, length: int) -> str:
    if kind == "aes256":
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    return secrets.token_urlsafe(length)


def complete(existing: dict) -> dict:
    out = dict(existing)
    for name, (kind, length) in SPEC.items():
        out.setdefault(name, generate(kind, length))
    return out


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "missing-json":
        json.dump(complete(json.load(sys.stdin)), sys.stdout)
    elif cmd == "ensure":
        root = Path(__file__).resolve().parent.parent / ".secrets"
        root.mkdir(exist_ok=True)
        for name, (kind, length) in SPEC.items():
            p = root / name
            if not p.exists():
                p.write_text(generate(kind, length))
                try:
                    os.chmod(p, 0o600)
                except OSError:
                    pass
                print(f"  créé : .secrets/{name}")
        print("secrets complets.")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
