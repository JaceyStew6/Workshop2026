#!/bin/sh
# Applique sur la base EXISTANTE la migration « habilitations + reconnaissance faciale » (idempotente, sans perte de données).
# Une base neuve l'applique d'elle-même (services/postgres/init/30-biometrics.sh) : ce script ne sert que pour une mise à jour.
#   sh tools/migrate_db.sh        (depuis WSL ou Git Bash, postgres démarré)
set -eu
cd "$(dirname "$0")/.."
docker compose exec -T postgres sh /docker-entrypoint-initdb.d/30-biometrics.sh
