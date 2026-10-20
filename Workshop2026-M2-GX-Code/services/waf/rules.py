"""Règles d'inspection (sous-ensemble inspiré d'OWASP CRS) avec score d'anomalie.

Fonctionnement identique au mode "anomaly scoring" de CRS : chaque règle qui correspond ajoute son
score ; la requête est bloquée si le total atteint BLOCK_THRESHOLD (5 = une règle critique suffit).
Les règles sont volontairement lisibles : c'est un choix assumé (explicable en soutenance), pas une
prétention à égaler ModSecurity/Coraza avec le jeu CRS complet. Voir governance/ pour les limites.

Normalisation avant inspection : double décodage URL, suppression des commentaires SQL /* */,
compactage des espaces, minuscules. Le champ `password` n'est jamais inspecté (faux positifs).
"""
from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Iterable, List, Tuple

BLOCK_THRESHOLD = 5
MAX_INSPECT = 65536
UNINSPECTED_KEYS = {"password"}


@dataclass(frozen=True)
class Rule:
    id: str
    group: str
    score: int
    pattern: re.Pattern
    targets: Tuple[str, ...]          # uri | args | header | body
    msg: str


def _r(id_, group, score, pattern, targets, msg):
    return Rule(id_, group, score, re.compile(pattern, re.I), tuple(targets), msg)


RULES: List[Rule] = [
    # --- injection SQL
    _r("942100", "sqli", 5, r"\bunion\b(\s+all)?\s+select\b", ("uri", "args", "body", "header"), "UNION SELECT"),
    _r("942110", "sqli", 5, r"(['\")]\s*(or|and)\s+['\"(]?[\w.]+['\")]?\s*(=|<|>|like)\s*['\"(]?[\w.]+)|(\b(or|and)\s+\d+\s*=\s*\d+)",
       ("uri", "args", "body", "header"), "tautologie booléenne"),
    _r("942120", "sqli", 5, r"\b(sleep\s*\(\s*\d|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay)", ("uri", "args", "body", "header"), "injection temporelle"),
    _r("942130", "sqli", 5, r";\s*(drop|alter|truncate|insert|update|delete|create)\s+\w+", ("uri", "args", "body", "header"), "requête empilée / DDL"),
    _r("942140", "sqli", 5, r"\b(information_schema|pg_catalog|pg_shadow|sqlite_master|xp_cmdshell)\b", ("uri", "args", "body", "header"), "énumération du schéma"),
    _r("942150", "sqli", 3, r"['\"]\s*(--|#|;)", ("uri", "args", "body"), "terminaison par commentaire SQL"),
    # --- XSS
    _r("941100", "xss", 5, r"<\s*script\b", ("uri", "args", "body", "header"), "balise <script>"),
    _r("941110", "xss", 5, r"\bon(error|load|click|mouseover|focus|toggle)\s*=", ("uri", "args", "body", "header"), "gestionnaire d'événement"),
    _r("941120", "xss", 5, r"javascript\s*:", ("uri", "args", "body", "header"), "URI javascript:"),
    _r("941130", "xss", 4, r"<\s*(iframe|object|embed|svg)\b", ("uri", "args", "body"), "balise active"),
    # --- traversée de chemin / fichiers système
    _r("930100", "lfi", 5, r"(\.\./|\.\.\\)", ("uri", "args", "body"), "traversée de répertoire"),
    _r("930110", "lfi", 5, r"(/etc/(passwd|shadow|hosts)|c:\\windows|boot\.ini|/proc/self)", ("uri", "args", "body"), "fichier système"),
    # --- exécution de commandes
    _r("932100", "rce", 5, r"(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh|powershell|cmd)\b", ("uri", "args", "body"), "enchaînement de commande"),
    _r("932110", "rce", 5, r"(/bin/(ba)?sh\b|cmd\.exe|powershell(\.exe)?\s+-)", ("uri", "args", "body"), "interpréteur de commandes"),
    _r("944100", "rce", 5, r"\$\{\s*jndi\s*:", ("uri", "args", "body", "header"), "JNDI (type Log4Shell)"),
    # --- scanners connus
    _r("913100", "scanner", 5, r"(sqlmap|nikto|nmap|masscan|nuclei|acunetix|nessus|dirbuster|gobuster|wfuzz|hydra)", ("ua",), "outil de scan"),
]


def normalize(value: str) -> str:
    for _ in range(2):                                   # double encodage
        decoded = urllib.parse.unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    value = re.sub(r"/\*.*?\*/", " ", value, flags=re.S)  # commentaires SQL inline
    value = re.sub(r"\s+", " ", value)
    return value.lower()


def _json_strings(node, out: list):
    if isinstance(node, dict):
        for k, v in node.items():
            if k in UNINSPECTED_KEYS:
                continue
            out.append(str(k))
            _json_strings(v, out)
    elif isinstance(node, list):
        for v in node:
            _json_strings(v, out)
    elif isinstance(node, str):
        out.append(node)


def body_strings(body: bytes, content_type: str) -> List[str]:
    if not body:
        return []
    body = body[:MAX_INSPECT]
    if "json" in (content_type or "").lower():
        try:
            out: list = []
            _json_strings(json.loads(body), out)
            return out
        except (ValueError, UnicodeDecodeError):
            pass                                          # JSON invalide : on inspecte le brut
    return [body.decode("utf-8", "ignore")]


def inspect(path: str, query: str, headers: dict, body: bytes) -> Tuple[int, List[str]]:
    """Retourne (score, [ids de règles])."""
    targets = {
        "uri": [normalize(path)],
        "args": [normalize(query)] if query else [],
        "header": [normalize(headers.get(h, "")) for h in ("referer", "cookie", "x-forwarded-host") if headers.get(h)],
        "ua": [normalize(headers.get("user-agent", ""))],
        "body": [normalize(s) for s in body_strings(body, headers.get("content-type", ""))],
    }
    score, hits = 0, []
    for rule in RULES:
        for t in rule.targets:
            if any(rule.pattern.search(s) for s in targets.get(t, ())):
                score += rule.score
                hits.append(rule.id)
                break
    return score, hits


def should_block(score: int) -> bool:
    return score >= BLOCK_THRESHOLD
