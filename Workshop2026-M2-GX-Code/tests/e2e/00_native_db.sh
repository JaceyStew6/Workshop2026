#!/bin/sh
# Prépare une base PostgreSQL NATIVE jetable pour les tests sans Docker (bac à sable / debug).
# Usage : RUN=/tmp/ra-run sh tests/e2e/00_native_db.sh   (PostgreSQL 16 déjà installé et démarré)
set -eu
RUN="${RUN:-/tmp/ra-run}"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$RUN/.secrets"; chmod 755 "$RUN" "$RUN/.secrets"   # banc d essai jetable uniquement
gen() { [ -f "$RUN/.secrets/$1" ] || python3 -c "import secrets;print(secrets.token_urlsafe(24))" > "$RUN/.secrets/$1"; }
for s in db_password jwt_secret remediation_token waf_admin_token probe_password demo_password; do gen "$s"; done
chmod 644 "$RUN/.secrets/"*      # postgres (autre UID) doit pouvoir lire le secret pour 20-roles.sh

PW="$(cat "$RUN/.secrets/db_password")"
su postgres -c "psql -v ON_ERROR_STOP=1 -c \"DROP DATABASE IF EXISTS payments\"" >/dev/null
su postgres -c "psql -v ON_ERROR_STOP=1 -c \"DROP ROLE IF EXISTS auth_svc\"" >/dev/null 2>&1 || true
su postgres -c "psql -c \"DROP ROLE IF EXISTS payment_svc\"" >/dev/null 2>&1 || true
su postgres -c "psql -c \"DROP ROLE IF EXISTS gate_svc\"" >/dev/null 2>&1 || true
su postgres -c "psql -c \"DROP ROLE IF EXISTS postgres_admin\"" >/dev/null 2>&1 || true
su postgres -c "psql -v ON_ERROR_STOP=1 -c \"CREATE ROLE postgres_admin SUPERUSER LOGIN\" -c \"CREATE DATABASE payments OWNER postgres_admin\"" >/dev/null
su postgres -c "psql -v ON_ERROR_STOP=1 -d payments -f $HERE/services/postgres/init/10-schema.sql" >/dev/null
su postgres -c "POSTGRES_USER=postgres POSTGRES_DB=payments DB_PASSWORD_FILE=$RUN/.secrets/db_password sh $HERE/services/postgres/init/20-roles.sh"
su postgres -c "POSTGRES_USER=postgres POSTGRES_DB=payments DB_PASSWORD_FILE=$RUN/.secrets/db_password sh $HERE/services/postgres/init/30-biometrics.sh" >/dev/null
echo "base prête : payments / rôles auth_svc, payment_svc (secrets dans $RUN/.secrets)"
