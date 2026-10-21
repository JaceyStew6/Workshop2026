"""Simulateur de l'ESP8266 : interroge la passerelle comme le vrai firmware et affiche le voyant dans le terminal.

  python firmware/esp8266-led/sim/led_sim.py --base http://127.0.0.1 [--seconds 120]

Même protocole que src/main.cpp : GET /gate/device/led toutes les secondes avec l'en-tête X-Device-Token ; motif
reproduit localement (clignotement 1 Hz) ; extinction sûre si la passerelle ne répond plus pendant 5 s.
Utile pour voir le voyant sans matériel pendant que quelqu'un se connecte au back-office.
"""
import argparse
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[3]
GLYPH = {"off": "  .  éteint", "green_blink": " (V) vert clignotant", "green_solid": " [V] vert fixe",
         "red_blink": " (R) rouge clignotant", "red_solid": " [R] rouge fixe"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1")
    ap.add_argument("--seconds", type=float, default=120)
    a = ap.parse_args()
    token = (ROOT / ".secrets" / "device_token").read_text().strip()
    c = httpx.Client(timeout=1.2, headers={"X-Device-Token": token})
    last_ok, shown, t0 = time.time(), None, time.time()
    while time.time() - t0 < a.seconds:
        pattern = "off"
        try:
            r = c.get(a.base + "/gate/device/led")
            if r.status_code == 200:
                last_ok, pattern = time.time(), r.json()["pattern"]
            else:
                print(f"HTTP {r.status_code}", file=sys.stderr)
        except httpx.HTTPError:
            pass
        if time.time() - last_ok > 5:
            pattern = "off"                      # échec sûr
        if pattern != shown:
            print(f"{time.strftime('%H:%M:%S')} {GLYPH[pattern]}", flush=True)
            shown = pattern
        time.sleep(1.0)


if __name__ == "__main__":
    main()
