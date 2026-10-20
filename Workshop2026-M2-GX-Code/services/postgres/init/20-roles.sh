#!/bin/sh
# Rôles à privilèges minimaux. Le mot de passe vient du secret Docker (jamais d'un fichier versionné).
# Dans ce prototype les deux rôles partagent le même secret ; en industriel : un secret par service.
set -eu
PW="$(cat "${DB_PASSWORD_FILE:-/run/secrets/db_password}")"

psql -v ON_ERROR_STOP=1 -v pw="$PW" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE auth_svc    LOGIN PASSWORD :'pw' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE payment_svc LOGIN PASSWORD :'pw' NOSUPERUSER NOCREATEDB NOCREATEROLE;

GRANT CONNECT ON DATABASE payments TO auth_svc, payment_svc;
GRANT USAGE ON SCHEMA public TO auth_svc, payment_svc;

-- auth-service : uniquement la table des utilisateurs
GRANT SELECT, INSERT, UPDATE ON users TO auth_svc;
GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO auth_svc;

-- payment-api : lit/modifie les soldes, journalise les transactions, lit l'invariant
GRANT SELECT, UPDATE ON accounts TO payment_svc;
GRANT SELECT, INSERT ON transactions TO payment_svc;
GRANT SELECT ON ledger_meta TO payment_svc;
SQL
