#!/bin/sh
# Déchiffre secrets/secrets.enc.yaml vers .secrets/<nom> (un fichier par secret, droits 600).
# Les conteneurs reçoivent ces fichiers comme Docker secrets (/run/secrets/<nom>), jamais en variable d'environnement.
set -eu
cd "$(dirname "$0")/.."
export SOPS_AGE_KEY_FILE="${SOPS_AGE_KEY_FILE:-$HOME/.config/sops/age/keys.txt}"
[ -f secrets/secrets.enc.yaml ] || { echo "lancez d'abord tools/init_secrets.sh"; exit 1; }
umask 077; mkdir -p .secrets
sops --decrypt --output-type json secrets/secrets.enc.yaml | python3 -c '
import json, sys, os
for k, v in json.load(sys.stdin).items():
    if not k.replace("_", "").isalnum():
        sys.exit("nom de secret invalide")
    with open(os.path.join(".secrets", k), "w") as f:
        f.write(v)
    os.chmod(os.path.join(".secrets", k), 0o600)
    print("  .secrets/" + k)
'
