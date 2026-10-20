#!/bin/sh
# Génère les secrets de la plateforme et les chiffre avec SOPS + age. À exécuter UNE FOIS, sur le PC Hôte (WSL2).
#   - crée la clé age de l'équipe si elle n'existe pas (clé privée : ~/.config/sops/age/keys.txt, jamais versionnée)
#   - génère des secrets aléatoires, les chiffre dans secrets/secrets.enc.yaml (versionnable)
#   - ne laisse AUCUN secret en clair sur disque en dehors de .secrets/ (voir render_secrets.sh)
# Prérequis : sops et age installés (https://github.com/getsops/sops, https://github.com/FiloSottile/age).
set -eu
cd "$(dirname "$0")/.."
KEYFILE="${SOPS_AGE_KEY_FILE:-$HOME/.config/sops/age/keys.txt}"
command -v sops >/dev/null || { echo "sops introuvable"; exit 1; }
command -v age-keygen >/dev/null || { echo "age-keygen introuvable"; exit 1; }

if [ ! -f "$KEYFILE" ]; then
  mkdir -p "$(dirname "$KEYFILE")"; umask 077
  age-keygen -o "$KEYFILE" 2>/dev/null
  echo "clé age créée : $KEYFILE  (SAUVEGARDEZ-LA hors dépôt : sans elle, les secrets sont irrécupérables)"
fi
PUB="$(grep -i 'public key' "$KEYFILE" | sed 's/.*: //')"
sed -i "s|age: .*|age: $PUB|" .sops.yaml

if [ -f secrets/secrets.enc.yaml ] && [ "${FORCE:-0}" != "1" ]; then
  echo "secrets/secrets.enc.yaml existe déjà (FORCE=1 pour régénérer : TOUS les mots de passe changent)"; exit 0
fi
gen() { python3 -c "import secrets;print(secrets.token_urlsafe(${1:-24}))"; }
TMP="$(mktemp)"; trap 'shred -u "$TMP" 2>/dev/null || rm -f "$TMP"' EXIT; chmod 600 "$TMP"
cat > "$TMP" <<YAML
db_password: $(gen)
jwt_secret: $(gen 48)
remediation_token: $(gen)
waf_admin_token: $(gen)
probe_password: $(gen)
demo_password: $(gen 16)
grafana_password: $(gen 16)
YAML
mkdir -p secrets
sops --encrypt --config .sops.yaml --filename-override secrets/secrets.enc.yaml "$TMP" > secrets/secrets.enc.yaml
echo "secrets/secrets.enc.yaml chiffré (7 secrets). Prochaine étape : sh tools/render_secrets.sh"
