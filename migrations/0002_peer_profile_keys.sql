-- Phase 5: peer profile keys. Populated from inbound DataMessage.profile_key;
-- the sealed-sender outbound path derives the recipient's
-- Unidentified-Access-Key from this column. v0.1 has no SyncMessage::Contacts
-- backfill, so a peer's key is only known once they've sent us a message
-- carrying it.

CREATE TABLE peer_profile_keys (
    aci         TEXT PRIMARY KEY NOT NULL,
    profile_key BLOB NOT NULL,
    updated_ms  INTEGER NOT NULL
);
