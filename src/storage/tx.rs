//! `TxStore<'a, 'tx>` — a transaction-scoped wrapper that implements
//! libsignal-protocol's storage traits against a single in-flight
//! `sqlx::Transaction`. Used by the receive loop's decrypt critical
//! section so the session-state read/write happens atomically with
//! prekey consumption and any identity updates libsignal triggers.
//!
//! ## Disjoint per-trait wrappers
//!
//! `libsignal_protocol::message_decrypt` takes four `&mut dyn` storage
//! references plus one `&dyn`. Pointing all four `&mut`s at the same
//! `TxStore` instance is rejected by the borrow checker (multiple
//! mutable borrows of the same binding). To satisfy the signature while
//! preserving transactional atomicity, [`TxStore`] exposes per-trait
//! sub-stores ([`TxSessionStore`], [`TxIdentityStore`],
//! [`TxPreKeyStore`], [`TxSignedPreKeyStore`], [`TxKyberPreKeyStore`]).
//! Each sub-store holds a clone of the same `Rc<RefCell<&mut
//! Transaction>>`, so the runtime borrow checker (the `RefCell`) keeps
//! concurrent mutation at bay while the compile-time borrow checker
//! sees five independent bindings.
//!
//! ## Lifetime story
//!
//! `TxStore<'a, 'tx>` mutably borrows the transaction for the duration
//! of one logical decrypt. While the store and its sub-stores exist, no
//! other code can touch the transaction. Drop the sub-stores, drop the
//! `TxStore`, commit the transaction, and only then yield the decrypted
//! envelope to subscribers. If the decrypt panics or returns early, the
//! transaction is rolled back implicitly.

use std::cell::RefCell;
use std::rc::Rc;

use async_trait::async_trait;
use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, KyberPreKeyId,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, PublicKey,
    SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use log::debug;
use sqlx::{Row, Sqlite, Transaction};

/// Shared, runtime-borrow-checked handle on the in-flight transaction.
/// All five per-trait sub-stores hold a clone of this `Rc`; the
/// `RefCell` enforces sequential access at run time.
type TxRef<'a, 'tx> = Rc<RefCell<&'a mut Transaction<'tx, Sqlite>>>;

fn map_sqlx(e: sqlx::Error) -> SignalProtocolError {
    SignalProtocolError::InvalidArgument(format!("storage: {e}"))
}

/// Owning container for the transaction reference. Construct one per
/// envelope; call the `*_store()` methods to mint per-trait sub-stores
/// that satisfy `message_decrypt`'s four-disjoint-`&mut dyn` signature.
///
/// `TxStore` itself implements all five libsignal storage traits as a
/// convenience for callers that do not need to thread four disjoint
/// references through one function (tests, single-trait helpers).
pub struct TxStore<'a, 'tx> {
    inner: TxRef<'a, 'tx>,
}

impl<'a, 'tx> TxStore<'a, 'tx> {
    pub fn new(tx: &'a mut Transaction<'tx, Sqlite>) -> Self {
        Self {
            inner: Rc::new(RefCell::new(tx)),
        }
    }

    /// Per-trait sub-store. Each sub-store holds an independent
    /// `&mut`-able binding from the borrow checker's perspective while
    /// the underlying transaction is shared via [`Rc`].
    pub fn session_store(&self) -> TxSessionStore<'a, 'tx> {
        TxSessionStore {
            inner: Rc::clone(&self.inner),
        }
    }

    pub fn identity_store(&self) -> TxIdentityStore<'a, 'tx> {
        TxIdentityStore {
            inner: Rc::clone(&self.inner),
        }
    }

    pub fn pre_key_store(&self) -> TxPreKeyStore<'a, 'tx> {
        TxPreKeyStore {
            inner: Rc::clone(&self.inner),
        }
    }

    pub fn signed_pre_key_store(&self) -> TxSignedPreKeyStore<'a, 'tx> {
        TxSignedPreKeyStore {
            inner: Rc::clone(&self.inner),
        }
    }

    pub fn kyber_pre_key_store(&self) -> TxKyberPreKeyStore<'a, 'tx> {
        TxKyberPreKeyStore {
            inner: Rc::clone(&self.inner),
        }
    }
}

// =============================================================================
// Per-trait sub-stores. Each one implements exactly one libsignal trait.
// =============================================================================

pub struct TxSessionStore<'a, 'tx> {
    inner: TxRef<'a, 'tx>,
}

pub struct TxIdentityStore<'a, 'tx> {
    inner: TxRef<'a, 'tx>,
}

pub struct TxPreKeyStore<'a, 'tx> {
    inner: TxRef<'a, 'tx>,
}

pub struct TxSignedPreKeyStore<'a, 'tx> {
    inner: TxRef<'a, 'tx>,
}

pub struct TxKyberPreKeyStore<'a, 'tx> {
    inner: TxRef<'a, 'tx>,
}

// =============================================================================
// SessionStore - shared body used by both the per-trait sub-store and the
// combined TxStore wrapper. Hoisted so the impls don't duplicate SQL.
// =============================================================================

#[allow(clippy::await_holding_refcell_ref)]
async fn load_session_impl(
    inner: &TxRef<'_, '_>,
    address: &ProtocolAddress,
) -> Result<Option<SessionRecord>, SignalProtocolError> {
    let row = sqlx::query("SELECT record FROM sessions WHERE address = ?")
        .bind(address.to_string())
        .fetch_optional(&mut ***inner.borrow_mut())
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

#[allow(clippy::await_holding_refcell_ref)]
async fn store_session_impl(
    inner: &TxRef<'_, '_>,
    address: &ProtocolAddress,
    record: &SessionRecord,
) -> Result<(), SignalProtocolError> {
    debug!("TxStore::store_session: address={}", address);
    let bytes = record.serialize()?;
    sqlx::query("INSERT OR REPLACE INTO sessions (address, record) VALUES (?, ?)")
        .bind(address.to_string())
        .bind(bytes)
        .execute(&mut ***inner.borrow_mut())
        .await
        .map_err(map_sqlx)?;
    Ok(())
}

#[async_trait(?Send)]
impl SessionStore for TxSessionStore<'_, '_> {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>, SignalProtocolError> {
        load_session_impl(&self.inner, address).await
    }
    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        store_session_impl(&self.inner, address, record).await
    }
}

#[async_trait(?Send)]
impl SessionStore for TxStore<'_, '_> {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>, SignalProtocolError> {
        load_session_impl(&self.inner, address).await
    }
    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        store_session_impl(&self.inner, address, record).await
    }
}

// =============================================================================
// IdentityKeyStore
// =============================================================================

#[allow(clippy::await_holding_refcell_ref)]
async fn get_identity_key_pair_impl(inner: &TxRef<'_, '_>) -> Result<IdentityKeyPair, SignalProtocolError> {
    let row = sqlx::query("SELECT value FROM identity WHERE key = 'identity_keypair'")
        .fetch_optional(&mut ***inner.borrow_mut())
        .await
        .map_err(map_sqlx)?
        .ok_or_else(|| SignalProtocolError::InvalidArgument("identity_keypair not persisted".into()))?;
    let bytes = row.get::<Vec<u8>, _>("value");
    IdentityKeyPair::try_from(&bytes[..])
}

#[allow(clippy::await_holding_refcell_ref)]
async fn get_local_registration_id_impl(inner: &TxRef<'_, '_>) -> Result<u32, SignalProtocolError> {
    let row = sqlx::query("SELECT value FROM identity WHERE key = 'registration_id'")
        .fetch_optional(&mut ***inner.borrow_mut())
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

#[allow(clippy::await_holding_refcell_ref)]
async fn save_identity_impl(
    inner: &TxRef<'_, '_>,
    address: &ProtocolAddress,
    identity: &IdentityKey,
) -> Result<IdentityChange, SignalProtocolError> {
    debug!("TxStore::save_identity: address={}", address);
    let key = address.to_string();
    let new_key_bytes = identity.serialize();
    let existing = sqlx::query("SELECT key FROM identities WHERE address = ?")
        .bind(&key)
        .fetch_optional(&mut ***inner.borrow_mut())
        .await
        .map_err(map_sqlx)?
        .map(|r| r.get::<Vec<u8>, _>("key"));
    sqlx::query("INSERT OR REPLACE INTO identities (address, key) VALUES (?, ?)")
        .bind(&key)
        .bind(new_key_bytes.as_ref())
        .execute(&mut ***inner.borrow_mut())
        .await
        .map_err(map_sqlx)?;
    Ok(match existing {
        Some(prev) if prev.as_slice() == new_key_bytes.as_ref() => IdentityChange::NewOrUnchanged,
        Some(_) => IdentityChange::ReplacedExisting,
        None => IdentityChange::NewOrUnchanged,
    })
}

#[allow(clippy::await_holding_refcell_ref)]
async fn is_trusted_identity_impl(
    inner: &TxRef<'_, '_>,
    address: &ProtocolAddress,
    identity: &IdentityKey,
) -> Result<bool, SignalProtocolError> {
    let row = sqlx::query("SELECT key FROM identities WHERE address = ?")
        .bind(address.to_string())
        .fetch_optional(&mut ***inner.borrow_mut())
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

#[allow(clippy::await_holding_refcell_ref)]
async fn get_identity_impl(
    inner: &TxRef<'_, '_>,
    address: &ProtocolAddress,
) -> Result<Option<IdentityKey>, SignalProtocolError> {
    let row = sqlx::query("SELECT key FROM identities WHERE address = ?")
        .bind(address.to_string())
        .fetch_optional(&mut ***inner.borrow_mut())
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

#[async_trait(?Send)]
impl IdentityKeyStore for TxIdentityStore<'_, '_> {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        get_identity_key_pair_impl(&self.inner).await
    }
    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        get_local_registration_id_impl(&self.inner).await
    }
    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        save_identity_impl(&self.inner, address, identity).await
    }
    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        is_trusted_identity_impl(&self.inner, address, identity).await
    }
    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>, SignalProtocolError> {
        get_identity_impl(&self.inner, address).await
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for TxStore<'_, '_> {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        get_identity_key_pair_impl(&self.inner).await
    }
    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        get_local_registration_id_impl(&self.inner).await
    }
    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        save_identity_impl(&self.inner, address, identity).await
    }
    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        is_trusted_identity_impl(&self.inner, address, identity).await
    }
    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>, SignalProtocolError> {
        get_identity_impl(&self.inner, address).await
    }
}

// =============================================================================
// PreKeyStore
// =============================================================================

#[allow(clippy::await_holding_refcell_ref)]
async fn get_pre_key_impl(inner: &TxRef<'_, '_>, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
    let id: u32 = prekey_id.into();
    let row = sqlx::query("SELECT record FROM prekeys WHERE id = ?")
        .bind(id as i64)
        .fetch_optional(&mut ***inner.borrow_mut())
        .await
        .map_err(map_sqlx)?
        .ok_or(SignalProtocolError::InvalidPreKeyId)?;
    let bytes = row.get::<Vec<u8>, _>("record");
    PreKeyRecord::deserialize(&bytes)
}

#[allow(clippy::await_holding_refcell_ref)]
async fn save_pre_key_impl(
    inner: &TxRef<'_, '_>,
    prekey_id: PreKeyId,
    record: &PreKeyRecord,
) -> Result<(), SignalProtocolError> {
    let id: u32 = prekey_id.into();
    let bytes = record.serialize()?;
    sqlx::query("INSERT OR REPLACE INTO prekeys (id, record) VALUES (?, ?)")
        .bind(id as i64)
        .bind(bytes)
        .execute(&mut ***inner.borrow_mut())
        .await
        .map_err(map_sqlx)?;
    Ok(())
}

#[allow(clippy::await_holding_refcell_ref)]
async fn remove_pre_key_impl(inner: &TxRef<'_, '_>, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
    let id: u32 = prekey_id.into();
    debug!("TxStore::remove_pre_key: id={}", id);
    sqlx::query("DELETE FROM prekeys WHERE id = ?")
        .bind(id as i64)
        .execute(&mut ***inner.borrow_mut())
        .await
        .map_err(map_sqlx)?;
    Ok(())
}

#[async_trait(?Send)]
impl PreKeyStore for TxPreKeyStore<'_, '_> {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        get_pre_key_impl(&self.inner, prekey_id).await
    }
    async fn save_pre_key(&mut self, prekey_id: PreKeyId, record: &PreKeyRecord) -> Result<(), SignalProtocolError> {
        save_pre_key_impl(&self.inner, prekey_id, record).await
    }
    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        remove_pre_key_impl(&self.inner, prekey_id).await
    }
}

#[async_trait(?Send)]
impl PreKeyStore for TxStore<'_, '_> {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        get_pre_key_impl(&self.inner, prekey_id).await
    }
    async fn save_pre_key(&mut self, prekey_id: PreKeyId, record: &PreKeyRecord) -> Result<(), SignalProtocolError> {
        save_pre_key_impl(&self.inner, prekey_id, record).await
    }
    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        remove_pre_key_impl(&self.inner, prekey_id).await
    }
}

// =============================================================================
// SignedPreKeyStore
// =============================================================================

#[allow(clippy::await_holding_refcell_ref)]
async fn get_signed_pre_key_impl(
    inner: &TxRef<'_, '_>,
    signed_prekey_id: SignedPreKeyId,
) -> Result<SignedPreKeyRecord, SignalProtocolError> {
    let id: u32 = signed_prekey_id.into();
    let row = sqlx::query("SELECT record FROM signed_prekeys WHERE id = ?")
        .bind(id as i64)
        .fetch_optional(&mut ***inner.borrow_mut())
        .await
        .map_err(map_sqlx)?
        .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?;
    let bytes = row.get::<Vec<u8>, _>("record");
    SignedPreKeyRecord::deserialize(&bytes)
}

#[allow(clippy::await_holding_refcell_ref)]
async fn save_signed_pre_key_impl(
    inner: &TxRef<'_, '_>,
    signed_prekey_id: SignedPreKeyId,
    record: &SignedPreKeyRecord,
) -> Result<(), SignalProtocolError> {
    let id: u32 = signed_prekey_id.into();
    let bytes = record.serialize()?;
    sqlx::query("INSERT OR REPLACE INTO signed_prekeys (id, record) VALUES (?, ?)")
        .bind(id as i64)
        .bind(bytes)
        .execute(&mut ***inner.borrow_mut())
        .await
        .map_err(map_sqlx)?;
    Ok(())
}

#[async_trait(?Send)]
impl SignedPreKeyStore for TxSignedPreKeyStore<'_, '_> {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        get_signed_pre_key_impl(&self.inner, signed_prekey_id).await
    }
    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        save_signed_pre_key_impl(&self.inner, signed_prekey_id, record).await
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for TxStore<'_, '_> {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        get_signed_pre_key_impl(&self.inner, signed_prekey_id).await
    }
    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        save_signed_pre_key_impl(&self.inner, signed_prekey_id, record).await
    }
}

// =============================================================================
// KyberPreKeyStore
// =============================================================================

#[allow(clippy::await_holding_refcell_ref)]
async fn get_kyber_pre_key_impl(
    inner: &TxRef<'_, '_>,
    kyber_prekey_id: KyberPreKeyId,
) -> Result<KyberPreKeyRecord, SignalProtocolError> {
    let id: u32 = kyber_prekey_id.into();
    let row = sqlx::query("SELECT record FROM kyber_prekeys WHERE id = ?")
        .bind(id as i64)
        .fetch_optional(&mut ***inner.borrow_mut())
        .await
        .map_err(map_sqlx)?
        .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?;
    let bytes = row.get::<Vec<u8>, _>("record");
    KyberPreKeyRecord::deserialize(&bytes)
}

#[allow(clippy::await_holding_refcell_ref)]
async fn save_kyber_pre_key_impl(
    inner: &TxRef<'_, '_>,
    kyber_prekey_id: KyberPreKeyId,
    record: &KyberPreKeyRecord,
) -> Result<(), SignalProtocolError> {
    let id: u32 = kyber_prekey_id.into();
    let bytes = record.serialize()?;
    sqlx::query("INSERT OR REPLACE INTO kyber_prekeys (id, record, used) VALUES (?, ?, 0)")
        .bind(id as i64)
        .bind(bytes)
        .execute(&mut ***inner.borrow_mut())
        .await
        .map_err(map_sqlx)?;
    Ok(())
}

#[allow(clippy::await_holding_refcell_ref)]
async fn mark_kyber_pre_key_used_impl(
    inner: &TxRef<'_, '_>,
    kyber_prekey_id: KyberPreKeyId,
) -> Result<(), SignalProtocolError> {
    let id: u32 = kyber_prekey_id.into();
    debug!("TxStore::mark_kyber_pre_key_used: id={}", id);
    sqlx::query("DELETE FROM kyber_prekeys WHERE id = ?")
        .bind(id as i64)
        .execute(&mut ***inner.borrow_mut())
        .await
        .map_err(map_sqlx)?;
    Ok(())
}

#[async_trait(?Send)]
impl KyberPreKeyStore for TxKyberPreKeyStore<'_, '_> {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        get_kyber_pre_key_impl(&self.inner, kyber_prekey_id).await
    }
    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        save_kyber_pre_key_impl(&self.inner, kyber_prekey_id, record).await
    }
    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        _ec_prekey_id: SignedPreKeyId,
        _base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        mark_kyber_pre_key_used_impl(&self.inner, kyber_prekey_id).await
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for TxStore<'_, '_> {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        get_kyber_pre_key_impl(&self.inner, kyber_prekey_id).await
    }
    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        save_kyber_pre_key_impl(&self.inner, kyber_prekey_id, record).await
    }
    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        _ec_prekey_id: SignedPreKeyId,
        _base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        mark_kyber_pre_key_used_impl(&self.inner, kyber_prekey_id).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
