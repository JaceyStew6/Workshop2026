"""Liste de bannissement avec TTL, plafonds et persistance.

Garde-fous (la remédiation a un pouvoir de blocage : il doit être borné) :
  * une seule IP par ban (pas de CIDR) : impossible de bloquer un réseau entier par erreur
  * jamais : loopback, non spécifiée, multicast, liste NEVER_BAN (ex. PC Hôte)
  * TTL plafonné, nombre de bans actifs plafonné
  * persistance atomique : un redémarrage du WAF ne "débannit" pas l'attaquant
"""
from __future__ import annotations

import ipaddress
import json
import os
import time
from typing import Dict, Optional


class BanRefused(Exception):
    pass


class BanList:
    def __init__(self, path: Optional[str] = None, never_ban=(), max_ttl: int = 3600, max_active: int = 100):
        self.path = path
        self.never = {ipaddress.ip_address(x.strip()) for x in never_ban if x.strip()}
        self.max_ttl, self.max_active = max_ttl, max_active
        self._bans: Dict[str, dict] = {}
        self._load()

    def _load(self):
        if self.path and os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    self._bans = json.load(f)
            except (OSError, ValueError):
                self._bans = {}

    def _save(self):
        if not self.path:
            return
        tmp = f"{self.path}.tmp"
        with open(tmp, "w") as f:
            json.dump(self._bans, f)
        os.replace(tmp, self.path)

    def _purge(self):
        now = time.time()
        expired = [ip for ip, b in self._bans.items() if b["expires"] <= now]
        for ip in expired:
            del self._bans[ip]
        if expired:
            self._save()

    def ban(self, ip: str, ttl: int, reason: str, incident_id: str = "", by: str = "") -> dict:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            raise BanRefused("adresse IP invalide (une seule IP, pas de réseau)")
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr in self.never:
            raise BanRefused("adresse protégée (anti-lockout)")
        self._purge()
        if str(addr) not in self._bans and len(self._bans) >= self.max_active:
            raise BanRefused("plafond de bans actifs atteint")
        ttl = max(1, min(int(ttl), self.max_ttl))
        entry = {"expires": time.time() + ttl, "reason": reason[:200], "incident_id": incident_id[:64],
                 "by": by[:64], "since": time.time(), "ttl": ttl}
        self._bans[str(addr)] = entry
        self._save()
        return entry

    def unban(self, ip: str) -> bool:
        removed = self._bans.pop(ip, None) is not None
        if removed:
            self._save()
        return removed

    def is_banned(self, ip: str) -> bool:
        b = self._bans.get(ip)
        if not b:
            return False
        if b["expires"] <= time.time():
            del self._bans[ip]
            self._save()
            return False
        return True

    def active(self) -> Dict[str, dict]:
        self._purge()
        return dict(self._bans)
