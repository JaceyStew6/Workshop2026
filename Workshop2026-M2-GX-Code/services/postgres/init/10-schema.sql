-- Schéma du SI de paiement FICTIF. Aucune donnée réelle.
-- Exécuté une seule fois à l'initialisation du volume (docker-entrypoint-initdb.d).

CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('user', 'probe')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE accounts (
    id         TEXT PRIMARY KEY,
    owner      TEXT NOT NULL,                       -- username propriétaire
    balance    NUMERIC(16,2) NOT NULL CHECK (balance >= 0),
    currency   CHAR(3) NOT NULL DEFAULT 'EUR'
);

CREATE TABLE transactions (
    id              UUID PRIMARY KEY,
    src             TEXT NOT NULL REFERENCES accounts(id),
    dst             TEXT NOT NULL REFERENCES accounts(id),
    amount          NUMERIC(16,2) NOT NULL CHECK (amount > 0),
    status          TEXT NOT NULL CHECK (status IN ('COMPLETED', 'REJECTED')),
    idempotency_key TEXT UNIQUE,
    created_by      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX transactions_created_at_idx ON transactions (created_at DESC);

-- Invariant d'intégrité : la somme des soldes ne change jamais (un paiement déplace de l'argent,
-- il n'en crée pas). La sonde de remédiation le vérifie après chaque reprise.
CREATE TABLE ledger_meta (
    key   TEXT PRIMARY KEY,
    value NUMERIC(20,2) NOT NULL
);

INSERT INTO accounts (id, owner, balance) VALUES
    ('ACC-DEMO-1', 'demo-user',       1000000000.00),
    ('ACC-DEMO-2', 'demo-user',       1000000000.00),
    ('PROBE-A',    'synthetic-probe', 1000000.00),
    ('PROBE-B',    'synthetic-probe', 1000000.00);

INSERT INTO ledger_meta (key, value)
    SELECT 'expected_total', COALESCE(SUM(balance), 0) FROM accounts;
