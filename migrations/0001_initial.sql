-- v0.1 schema. Singleton-row tables are keyed by a TEXT primary key; per-peer
-- and per-key tables are keyed naturally.

CREATE TABLE identity (
    key   TEXT PRIMARY KEY NOT NULL,
    value BLOB NOT NULL
);

CREATE TABLE sessions (
    address TEXT PRIMARY KEY NOT NULL,
    record  BLOB NOT NULL
);

CREATE TABLE prekeys (
    id     INTEGER PRIMARY KEY NOT NULL,
    record BLOB NOT NULL
);

CREATE TABLE signed_prekeys (
    id     INTEGER PRIMARY KEY NOT NULL,
    record BLOB NOT NULL
);

CREATE TABLE kyber_prekeys (
    id     INTEGER PRIMARY KEY NOT NULL,
    record BLOB NOT NULL,
    used   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE identities (
    address TEXT PRIMARY KEY NOT NULL,
    key     BLOB NOT NULL
);
