#!/bin/sh
# Migration « Consigne additionnelle 1 » : habilitations (rôles + permissions), reconnaissance faciale, journal d'audit.
# IDEMPOTENTE : exécutée à l'initialisation d'un volume neuf (docker-entrypoint-initdb.d) ET relançable sur une base
# existante par `sh tools/migrate_db.sh` (ou le playbook Ansible), sans perte de données.
set -eu
PW="$(cat "${DB_PASSWORD_FILE:-/run/secrets/db_password}")"

psql -v ON_ERROR_STOP=1 -v pw="$PW" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
-- ---------------------------------------------------------------- rôles et permissions
CREATE TABLE IF NOT EXISTS roles (
    name        TEXT PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9_-]{1,31}$'),
    description TEXT NOT NULL DEFAULT '',
    permissions TEXT[] NOT NULL DEFAULT '{}',
    system      BOOLEAN NOT NULL DEFAULT false      -- rôles d'origine : non supprimables
);

INSERT INTO roles (name, description, permissions, system) VALUES
  ('admin',    'Administrateur : utilisateurs, rôles, visages, dispositif, audit',
     ARRAY['backoffice:access','backoffice:users','backoffice:roles','backoffice:faces','backoffice:device','backoffice:audit','payments:read'], true),
  ('operator', 'Opérateur : gestion des visages, dispositif et consultation de l''audit',
     ARRAY['backoffice:access','backoffice:faces','backoffice:device','backoffice:audit','payments:read'], true),
  ('user',     'Client du portail de paiement',
     ARRAY['payments:create','payments:read'], true),
  ('probe',    'Sonde synthétique de supervision (compte machine)',
     ARRAY['payments:create','payments:read'], true)
ON CONFLICT (name) DO NOTHING;

-- ---------------------------------------------------------------- utilisateurs
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD COLUMN IF NOT EXISTS face_required BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS active        BOOLEAN NOT NULL DEFAULT true;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_role_fk') THEN
    ALTER TABLE users ADD CONSTRAINT users_role_fk FOREIGN KEY (role) REFERENCES roles(name);
  END IF;
END $$;

-- ---------------------------------------------------------------- empreintes faciales (chiffrées par face-gate)
-- Jamais d'image : uniquement un vecteur de 128 nombres, chiffré en AES-GCM avant d'arriver ici.
CREATE TABLE IF NOT EXISTS face_templates (
    id         BIGSERIAL PRIMARY KEY,
    username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    label      TEXT NOT NULL DEFAULT '',
    nonce      BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    samples    INT NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS face_templates_user_idx ON face_templates (username);

-- ---------------------------------------------------------------- journal d'audit applicatif
CREATE TABLE IF NOT EXISTS audit_log (
    id     BIGSERIAL PRIMARY KEY,
    ts     TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    detail JSONB NOT NULL DEFAULT '{}',
    ip     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log (ts DESC);

-- ---------------------------------------------------------------- compte SQL de face-gate
SELECT format('CREATE ROLE gate_svc LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE', :'pw')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gate_svc')
\gexec
GRANT CONNECT ON DATABASE payments TO gate_svc;
GRANT USAGE ON SCHEMA public TO gate_svc;

-- Privilèges minimaux, par colonne quand c'est possible
-- auth-service : gère utilisateurs et rôles (pas de DELETE sur users : on désactive), lit le nombre d'empreintes
GRANT SELECT, INSERT, UPDATE ON users TO auth_svc;
GRANT SELECT, INSERT, UPDATE, DELETE ON roles TO auth_svc;
GRANT SELECT (id, username) ON face_templates TO auth_svc;
GRANT SELECT, INSERT ON audit_log TO auth_svc;
GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO auth_svc;
-- payment-api : aucune table nouvelle (les permissions arrivent dans le JWT)

-- face-gate : lit l'identité de l'utilisateur, gère les empreintes, active l'exigence faciale à la 1re inscription
GRANT SELECT (username, role, face_required, active) ON users TO gate_svc;
GRANT UPDATE (face_required) ON users TO gate_svc;
GRANT SELECT, INSERT, DELETE ON face_templates TO gate_svc;
GRANT USAGE, SELECT ON SEQUENCE face_templates_id_seq TO gate_svc;
GRANT SELECT, INSERT ON audit_log TO gate_svc;
GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO gate_svc;
SQL
echo "migration 30-biometrics appliquée"
