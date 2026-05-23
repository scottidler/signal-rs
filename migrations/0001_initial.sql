-- v0.1 schema. Singleton-row tables are keyed by a TEXT primary key; per-peer
-- tables are keyed by address. Prekey tables carry an `identity_kind`
-- column so ACI and PNI batches can coexist with overlapping `id` values
-- (libsignal-protocol's PreKeyStore traits key on `id` alone; the
-- discriminator lives at the SQL layer via the IdentityScopedStore wrapper).

CREATE TABLE identity (
    key   TEXT PRIMARY KEY NOT NULL,
    value BLOB NOT NULL
);

CREATE TABLE sessions (
    address TEXT PRIMARY KEY NOT NULL,
    record  BLOB NOT NULL
);

CREATE TABLE prekeys (
    identity_kind TEXT NOT NULL CHECK (identity_kind IN ('aci', 'pni')),
    id            INTEGER NOT NULL,
    record        BLOB    NOT NULL,
    PRIMARY KEY (identity_kind, id)
);

CREATE TABLE signed_prekeys (
    identity_kind TEXT NOT NULL CHECK (identity_kind IN ('aci', 'pni')),
    id            INTEGER NOT NULL,
    record        BLOB    NOT NULL,
    PRIMARY KEY (identity_kind, id)
);

CREATE TABLE kyber_prekeys (
    identity_kind TEXT NOT NULL CHECK (identity_kind IN ('aci', 'pni')),
    id            INTEGER NOT NULL,
    record        BLOB    NOT NULL,
    used          INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (identity_kind, id)
);

CREATE TABLE identities (
    address TEXT PRIMARY KEY NOT NULL,
    key     BLOB NOT NULL
);
