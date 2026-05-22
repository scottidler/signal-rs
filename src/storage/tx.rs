//! `TxStore<'a, 'tx>` — a transaction-scoped wrapper that implements
//! libsignal-protocol's storage traits against a single in-flight
//! `sqlx::Transaction`. Used by the receive loop's decrypt critical
//! section so the session-state read/write happens atomically with
//! prekey consumption and any identity updates libsignal triggers.
//!
//! The lifetime story: `TxStore<'a, 'tx>` mutably borrows the
//! transaction for the duration of one logical decrypt. While it
//! exists, no other code can touch the transaction. Drop the store,
//! commit the transaction, and only then yield the decrypted envelope
//! to subscribers. If the decrypt panics or returns early, the
//! transaction is rolled back implicitly.

use std::cell::RefCell;

use async_trait::async_trait;
use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, KyberPreKeyId,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, PublicKey,
    SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use log::debug;
use sqlx::{Row, Sqlite, Transaction};

/// Scoped store backed by a borrowed transaction. Constructed by the
/// receive loop before each decrypt; dropped before the transaction is
/// committed.
///
/// **Why `RefCell`**: libsignal-protocol's storage traits take `&self` for
/// reads and `&mut self` for writes, but `sqlx::Executor` requires
/// `&mut Connection` for every query (including reads). The two cannot be
/// reconciled without interior mutability. We use [`RefCell`] because
/// these futures are `!Send` (the `?Send` async_trait variant) and stay
/// pinned to one tokio task, so the `Cell` discipline is safe: each
/// borrow_mut is released at the end of one libsignal-method body before
/// the next storage call begins. No reentrant calls cross the borrow.
pub struct TxStore<'a, 'tx> {
    pub(crate) tx: RefCell<&'a mut Transaction<'tx, Sqlite>>,
}

impl<'a, 'tx> TxStore<'a, 'tx> {
    pub fn new(tx: &'a mut Transaction<'tx, Sqlite>) -> Self {
        Self { tx: RefCell::new(tx) }
    }
}

fn map_sqlx(e: sqlx::Error) -> SignalProtocolError {
    SignalProtocolError::InvalidArgument(format!("storage: {e}"))
}

// Clippy correctly flags `RefCell::borrow_mut` held across .await as a footgun
// in the general case. For TxStore the discipline is safe by construction:
// each &mut ***self.tx.borrow_mut() is a temporary that ends at the end of
// the call expression containing the await, and libsignal-protocol's storage
// traits never call back into TxStore reentrantly. The justification is
// documented on the struct.
#[allow(clippy::await_holding_refcell_ref)]
#[async_trait(?Send)]
impl IdentityKeyStore for TxStore<'_, '_> {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        let row = sqlx::query("SELECT value FROM identity WHERE key = 'identity_keypair'")
            .fetch_optional(&mut ***self.tx.borrow_mut())
            .await
            .map_err(map_sqlx)?
            .ok_or_else(|| SignalProtocolError::InvalidArgument("identity_keypair not persisted".into()))?;
        let bytes = row.get::<Vec<u8>, _>("value");
        IdentityKeyPair::try_from(&bytes[..])
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        let row = sqlx::query("SELECT value FROM identity WHERE key = 'registration_id'")
            .fetch_optional(&mut ***self.tx.borrow_mut())
            .await
            .map_err(map_sqlx)?
            .ok_or_else(|| SignalProtocolError::InvalidArgument("registration_id not persisted".into()))?;
        let bytes = row.get::<Vec<u8>, _>("value");
        let arr: [u8; 4] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| SignalProtocolError::InvalidArgument("registration_id length".into()))?;
        Ok(u32::from_be_bytes(arr))
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        debug!("TxStore::save_identity: address={}", address);
        let key = address.to_string();
        let new_key_bytes = identity.serialize();
        let existing = sqlx::query("SELECT key FROM identities WHERE address = ?")
            .bind(&key)
            .fetch_optional(&mut ***self.tx.borrow_mut())
            .await
            .map_err(map_sqlx)?
            .map(|r| r.get::<Vec<u8>, _>("key"));
        sqlx::query("INSERT OR REPLACE INTO identities (address, key) VALUES (?, ?)")
            .bind(&key)
            .bind(new_key_bytes.as_ref())
            .execute(&mut ***self.tx.borrow_mut())
            .await
            .map_err(map_sqlx)?;
        Ok(match existing {
            Some(prev) if prev.as_slice() == new_key_bytes.as_ref() => IdentityChange::NewOrUnchanged,
            Some(_) => IdentityChange::ReplacedExisting,
            None => IdentityChange::NewOrUnchanged,
        })
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        let row = sqlx::query("SELECT key FROM identities WHERE address = ?")
            .bind(address.to_string())
            .fetch_optional(&mut ***self.tx.borrow_mut())
            .await
            .map_err(map_sqlx)?;
        match row {
            None => Ok(true),
            Some(r) => {
                let stored = r.get::<Vec<u8>, _>("key");
                Ok(stored.as_slice() == identity.serialize().as_ref())
            }
        }
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let row = sqlx::query("SELECT key FROM identities WHERE address = ?")
            .bind(address.to_string())
            .fetch_optional(&mut ***self.tx.borrow_mut())
            .await
            .map_err(map_sqlx)?;
        match row {
            None => Ok(None),
            Some(r) => {
                let bytes = r.get::<Vec<u8>, _>("key");
                IdentityKey::decode(&bytes).map(Some)
            }
        }
    }
}

#[allow(clippy::await_holding_refcell_ref)]
#[async_trait(?Send)]
impl SessionStore for TxStore<'_, '_> {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let row = sqlx::query("SELECT record FROM sessions WHERE address = ?")
            .bind(address.to_string())
            .fetch_optional(&mut ***self.tx.borrow_mut())
            .await
            .map_err(map_sqlx)?;
        match row {
            None => Ok(None),
            Some(r) => {
                let bytes = r.get::<Vec<u8>, _>("record");
                SessionRecord::deserialize(&bytes).map(Some)
            }
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        debug!("TxStore::store_session: address={}", address);
        let bytes = record.serialize()?;
        sqlx::query("INSERT OR REPLACE INTO sessions (address, record) VALUES (?, ?)")
            .bind(address.to_string())
            .bind(bytes)
            .execute(&mut ***self.tx.borrow_mut())
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }
}

#[allow(clippy::await_holding_refcell_ref)]
#[async_trait(?Send)]
impl PreKeyStore for TxStore<'_, '_> {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let id: u32 = prekey_id.into();
        let row = sqlx::query("SELECT record FROM prekeys WHERE id = ?")
            .bind(id as i64)
            .fetch_optional(&mut ***self.tx.borrow_mut())
            .await
            .map_err(map_sqlx)?
            .ok_or(SignalProtocolError::InvalidPreKeyId)?;
        let bytes = row.get::<Vec<u8>, _>("record");
        PreKeyRecord::deserialize(&bytes)
    }

    async fn save_pre_key(&mut self, prekey_id: PreKeyId, record: &PreKeyRecord) -> Result<(), SignalProtocolError> {
        let id: u32 = prekey_id.into();
        let bytes = record.serialize()?;
        sqlx::query("INSERT OR REPLACE INTO prekeys (id, record) VALUES (?, ?)")
            .bind(id as i64)
            .bind(bytes)
            .execute(&mut ***self.tx.borrow_mut())
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        let id: u32 = prekey_id.into();
        debug!("TxStore::remove_pre_key: id={}", id);
        sqlx::query("DELETE FROM prekeys WHERE id = ?")
            .bind(id as i64)
            .execute(&mut ***self.tx.borrow_mut())
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }
}

#[allow(clippy::await_holding_refcell_ref)]
#[async_trait(?Send)]
impl SignedPreKeyStore for TxStore<'_, '_> {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let id: u32 = signed_prekey_id.into();
        let row = sqlx::query("SELECT record FROM signed_prekeys WHERE id = ?")
            .bind(id as i64)
            .fetch_optional(&mut ***self.tx.borrow_mut())
            .await
            .map_err(map_sqlx)?
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?;
        let bytes = row.get::<Vec<u8>, _>("record");
        SignedPreKeyRecord::deserialize(&bytes)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = signed_prekey_id.into();
        let bytes = record.serialize()?;
        sqlx::query("INSERT OR REPLACE INTO signed_prekeys (id, record) VALUES (?, ?)")
            .bind(id as i64)
            .bind(bytes)
            .execute(&mut ***self.tx.borrow_mut())
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }
}

#[allow(clippy::await_holding_refcell_ref)]
#[async_trait(?Send)]
impl KyberPreKeyStore for TxStore<'_, '_> {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        let row = sqlx::query("SELECT record FROM kyber_prekeys WHERE id = ?")
            .bind(id as i64)
            .fetch_optional(&mut ***self.tx.borrow_mut())
            .await
            .map_err(map_sqlx)?
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?;
        let bytes = row.get::<Vec<u8>, _>("record");
        KyberPreKeyRecord::deserialize(&bytes)
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        let bytes = record.serialize()?;
        sqlx::query("INSERT OR REPLACE INTO kyber_prekeys (id, record, used) VALUES (?, ?, 0)")
            .bind(id as i64)
            .bind(bytes)
            .execute(&mut ***self.tx.borrow_mut())
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        _ec_prekey_id: SignedPreKeyId,
        _base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        debug!("TxStore::mark_kyber_pre_key_used: id={}", id);
        sqlx::query("DELETE FROM kyber_prekeys WHERE id = ?")
            .bind(id as i64)
            .execute(&mut ***self.tx.borrow_mut())
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
