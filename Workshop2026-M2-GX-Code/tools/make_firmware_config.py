"""Génère firmware/esp8266-led/include/secrets.h (non versionné) : WiFi du hotspot + adresse de la passerelle + jeton de l'ESP.

  python tools/make_firmware_config.py --ssid MonHotspot [--host 192.168.137.1] [--port 80]
Le mot de passe WiFi est demandé au clavier (jamais en argument : il resterait dans l'historique du terminal).
Le jeton vient de .secrets/device_token (même secret que celui chargé dans face-gate).
"""
import argparse
import getpass
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def c_string(s: str) -> str:
    if re.search(r'[\x00-\x1f"\\]', s):
        raise SystemExit("caractère interdit (guillemet, antislash ou contrôle) dans une valeur")
    return f'"{s}"'


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ssid", required=True)
    ap.add_argument("--host", default="192.168.137.1", help="IP du PC Hôte sur le hotspot (HOST_IP du .env)")
    ap.add_argument("--port", type=int, default=80)
    a = ap.parse_args()
    pw = getpass.getpass(f"Mot de passe WiFi de « {a.ssid} » : ")
    token = (ROOT / ".secrets" / "device_token").read_text().strip()
    out = ROOT / "firmware" / "esp8266-led" / "include" / "secrets.h"
    out.write_text(
        "// GÉNÉRÉ par tools/make_firmware_config.py : ne pas versionner (déjà dans .gitignore).\n#pragma once\n"
        f"#define WIFI_SSID {c_string(a.ssid)}\n#define WIFI_PASS {c_string(pw)}\n"
        f"#define GATE_HOST {c_string(a.host)}\n#define GATE_PORT {a.port}\n#define DEVICE_TOKEN {c_string(token)}\n")
    print(f"écrit : {out.relative_to(ROOT)}  (hôte {a.host}:{a.port})")


if __name__ == "__main__":
    main()
