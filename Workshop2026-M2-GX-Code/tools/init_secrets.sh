#!/bin/sh
# Génère les secrets de la plateforme et les chiffre avec SOPS + age. À exécuter sur le PC Hôte (WSL2).
#   - crée la clé age de l'équipe si elle n'existe pas (clé privée : ~/.config/sops/age/keys.txt, jamais versionnée)
#   - génère des secrets aléatoires, les chiffre dans secrets/secrets.enc.yaml (versionnable)
#   - RELANÇABLE : si le fichier existe déjà, seuls les secrets MANQUANTS sont ajoutés (aucun mot de passe existant
#     ne change). FORCE=1 régénère TOUT (tous les mots de passe changent).
# Catalogue des secrets : tools/secrets_catalog.py. Prérequis : sops et age (https://github.com/getsops/sops).
set -eu
cd "$(dirname "$0")/.."
KEYFILE="${SOPS_AGE_KEY_FILE:-$HOME/.config/sops/age/keys.txt}"
export SOPS_AGE_KEY_FILE="$KEYFILE"
command -v sops >/dev/null || { echo "sops introuvable"; exit 1; }
command -v age-keygen >/dev/null || { echo "age-keygen introuvable"; exit 1; }

if [ ! -f "$KEYFILE" ]; then
  mkdir -p "$(dirname "$KEYFILE")"; umask 077
  age-keygen -o "$KEYFILE" 2>/dev/null
  echo "clé age créée : $KEYFILE  (SAUVEGARDEZ-LA hors dépôt : sans elle, les secrets sont irrécupérables)"
fi
PUB="$(grep -i 'public key' "$KEYFILE" | sed 's/.*: //')"
sed -i "s|age: .*|age: $PUB|" .sops.yaml

TMP="$(mktemp)"; trap 'shred -u "$TMP" 2>/dev/null || rm -f "$TMP"' EXIT; chmod 600 "$TMP"
mkdir -p secrets
if [ -f secrets/secrets.enc.yaml ] && [ "${FORCE:-0}" != "1" ]; then
  sops --decrypt --output-type json secrets/secrets.enc.yaml | python3 tools/secrets_catalog.py missing-json > "$TMP"
  BEFORE="$(sops --decrypt --output-type json secrets/secrets.enc.yaml | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))')"
  AFTER="$(python3 -c "import json;print(len(json.load(open('$TMP'))))")"
  if [ "$BEFORE" = "$AFTER" ]; then echo "secrets/secrets.enc.yaml déjà complet ($AFTER secrets)"; exit 0; fi
  echo "ajout de $((AFTER - BEFORE)) secret(s) manquant(s) (les existants ne changent pas)"
else
  echo '{}' | python3 tools/secrets_catalog.py missing-json > "$TMP"
fi
sops --encrypt --config .sops.yaml --input-type json --output-type yaml --filename-override secrets/secrets.enc.yaml "$TMP" > secrets/secrets.enc.yaml.new
mv secrets/secrets.enc.yaml.new secrets/secrets.enc.yaml
echo "secrets/secrets.enc.yaml chiffré. Prochaine étape : sh tools/render_secrets.sh"
