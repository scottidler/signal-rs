//! `TxStore` — a transaction-scoped wrapper that implements
//! libsignal-protocol's storage traits against a single in-flight
//! `sqlx::Transaction`. Used by the receive and send pipelines so the
//! session-state read/write happens atomically with prekey consumption
//! and any identity updates libsignal triggers.
//!
//! ## Ownership model
//!
//! The transaction is OWNED by [`TxStore`] (and shared with its
//! sub-stores via `Arc<tokio::sync::Mutex<Option<Transaction>>>`), not
//! borrowed. This means:
//!
//! 1. **`tokio::sync::Mutex` guards can be held across `.await`.** Unlike
//!    `RefCell::borrow_mut()`, the async mutex is explicitly designed for
//!    this and does not produce the `await_holding_refcell_ref` clippy
//!    lint. No `#[allow]` workaround required.
//!
//! 2. **Owning eliminates the lifetime-borrow friction.** Sub-stores no
//!    longer carry `'a, 'tx` lifetimes; they're plain types that own a
//!    cheap `Arc` clone.
//!
//! **Note on `Send`-ness.** `libsignal_protocol`'s storage traits are
//! declared `#[async_trait(?Send)]`, so the futures they return are
//! `!Send` *by trait contract*. Our impls match (also `?Send`). This
//! means `Client::process_envelope` and `Client::send_to_aci` remain
//! `!Send` regardless of which mutex we use — the constraint is upstream
//! of `TxStore`. Consumers wanting to `tokio::spawn` must either use a
//! current-thread runtime or `tokio::task::spawn_local`. The Arc/Mutex
//! switch is still worth doing because it cleans up the borrow-pattern
//! and removes the lint allow, but it does not, on its own, make the
//! receive/send futures `Send`.
//!
//! ## Disjoint per-trait wrappers
//!
//! `libsignal_protocol::message_decrypt` takes four `&mut dyn` storage
//! references plus one `&dyn`. Pointing all four `&mut`s at the same
//! `TxStore` is rejected by the borrow checker (multiple mutable
//! borrows of the same binding). [`TxStore`] exposes per-trait
//! sub-stores ([`TxSessionStore`], [`TxIdentityStore`],
//! [`TxPreKeyStore`], [`TxSignedPreKeyStore`], [`TxKyberPreKeyStore`]).
//! Each sub-store holds a clone of the same `Arc<Mutex<...>>`, so the
//! runtime mutex keeps concurrent mutation at bay while the
//! compile-time borrow checker sees five independent bindings.
//!
//! ## Commit / rollback
//!
//! Construct one `TxStore` per logical unit, hand out sub-stores, run
//! the libsignal call, drop the sub-stores, then call
//! [`TxStore::commit`] or let the `TxStore` drop to roll back. The
//! mutex is held only across individual SQL queries, not for the
//! entire lifetime of the store.

use std::sync::Arc;

use async_trait::async_trait;
use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, KyberPreKeyId,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, PublicKey,
    SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use log::{debug, trace};
use sqlx::{Row, Sqlite, Transaction};
use tokio::sync::Mutex;

/// Shared, async-mutex-guarded handle on the in-flight transaction. The
/// `Option` lets `TxStore::commit` take the transaction out for the
/// final commit() call; while sub-stores are running, the `Option` is
/// `Some(_)`.
type TxRef = Arc<Mutex<Option<Transaction<'static, Sqlite>>>>;

fn map_sqlx(e: sqlx::Error) -> SignalProtocolError {
    SignalProtocolError::InvalidArgument(format!("storage: {e}"))
}

fn tx_drained() -> SignalProtocolError {
    SignalProtocolError::InvalidArgument("TxStore: transaction already taken or rolled back".into())
}

/// Owning container for the transaction. Construct one per logical
/// unit; call `*_store()` methods to mint per-trait sub-stores;
/// finally call [`TxStore::commit`] or drop to roll back.
pub struct TxStore {
    inner: TxRef,
}

impl TxStore {
    pub fn new(tx: Transaction<'static, Sqlite>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(tx))),
        }
    }

    /// Commit the underlying transaction. Returns an error if the
    /// transaction has already been taken (programmer error).
    pub async fn commit(self) -> Result<(), sqlx::Error> {
        debug!("TxStore::commit:");
        let mut guard = self.inner.lock().await;
        let tx = guard
            .take()
            .ok_or_else(|| sqlx::Error::Configuration("TxStore::commit called twice".to_string().into()))?;
        drop(guard);
        tx.commit().await
    }

    /// Per-trait sub-store. Each sub-store holds an independent
    /// `&mut`-able binding from the borrow checker's perspective while
    /// the underlying transaction is shared via [`Arc`].
    pub fn session_store(&self) -> TxSessionStore {
        TxSessionStore {
            inner: Arc::clone(&self.inner),
        }
    }

    pub fn identity_store(&self) -> TxIdentityStore {
        TxIdentityStore {
            inner: Arc::clone(&self.inner),
        }
    }

    pub fn pre_key_store(&self) -> TxPreKeyStore {
        TxPreKeyStore {
            inner: Arc::clone(&self.inner),
        }
    }

    pub fn signed_pre_key_store(&self) -> TxSignedPreKeyStore {
        TxSignedPreKeyStore {
            inner: Arc::clone(&self.inner),
        }
    }

    pub fn kyber_pre_key_store(&self) -> TxKyberPreKeyStore {
        TxKyberPreKeyStore {
            inner: Arc::clone(&self.inner),
        }
    }
}

// =============================================================================
// Per-trait sub-stores
// =============================================================================

pub struct TxSessionStore {
    inner: TxRef,
}

pub struct TxIdentityStore {
    inner: TxRef,
}

pub struct TxPreKeyStore {
    inner: TxRef,
}

pub struct TxSignedPreKeyStore {
    inner: TxRef,
}

pub struct TxKyberPreKeyStore {
    inner: TxRef,
}

// =============================================================================
// SessionStore — shared SQL bodies hoisted to free functions
// =============================================================================

async fn load_session_impl(
    inner: &TxRef,
    address: &ProtocolAddress,
) -> Result<Option<SessionRecord>, SignalProtocolError> {
    trace!("TxStore::load_session: address={}", address);
    let mut guard = inner.lock().await;
    let tx = guard.as_mut().ok_or_else(tx_drained)?;
    let row = sqlx::query("SELECT record FROM sessions WHERE address = ?")
        .bind(address.to_string())
        .fetch_optional(&mut **tx)
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

async fn store_session_impl(
    inner: &TxRef,
    address: &ProtocolAddress,
    record: &SessionRecord,
) -> Result<(), SignalProtocolError> {
    debug!("TxStore::store_session: address={}", address);
    let bytes = record.serialize()?;
    let mut guard = inner.lock().await;
    let tx = guard.as_mut().ok_or_else(tx_drained)?;
    sqlx::query("INSERT OR REPLACE INTO sessions (address, record) VALUES (?, ?)")
        .bind(address.to_string())
        .bind(bytes)
        .execute(&mut **tx)
        .await
        .map_err(map_sqlx)?;
    Ok(())
}

#[async_trait(?Send)]
impl SessionStore for TxSessionStore {
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
impl SessionStore for TxStore {
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

async fn get_identity_key_pair_impl(inner: &TxRef) -> Result<IdentityKeyPair, SignalProtocolError> {
    trace!("TxStore::get_identity_key_pair:");
    let mut guard = inner.lock().await;
    let tx = guard.as_mut().ok_or_else(tx_drained)?;
    let row = sqlx::query("SELECT value FROM identity WHERE key = 'identity_keypair'")
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_sqlx)?
        .ok_or_else(|| SignalProtocolError::InvalidArgument("identity_keypair not persisted".into()))?;
    let bytes = row.get::<Vec<u8>, _>("value");
    IdentityKeyPair::try_from(&bytes[..])
}

async fn get_local_registration_id_impl(inner: &TxRef) -> Result<u32, SignalProtocolError> {
    trace!("TxStore::get_local_registration_id:");
    let mut guard = inner.lock().await;
    let tx = guard.as_mut().ok_or_else(tx_drained)?;
    let row = sqlx::query("SELECT value FROM identity WHERE key = 'registration_id'")
        .fetch_optional(&mut **tx)
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

async fn save_identity_impl(
    inner: &TxRef,
    address: &ProtocolAddress,
    identity: &IdentityKey,
) -> Result<IdentityChange, SignalProtocolError> {
    debug!("TxStore::save_identity: address={}", address);
    let key = address.to_string();
    let new_key_bytes = identity.serialize();
    let mut guard = inner.lock().await;
    let tx = guard.as_mut().ok_or_else(tx_drained)?;
    let existing = sqlx::query("SELECT key FROM identities WHERE address = ?")
        .bind(&key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_sqlx)?
        .map(|r| r.get::<Vec<u8>, _>("key"));
    sqlx::query("INSERT OR REPLACE INTO identities (address, key) VALUES (?, ?)")
        .bind(&key)
        .bind(new_key_bytes.as_ref())
        .execute(&mut **tx)
        .await
        .map_err(map_sqlx)?;
    Ok(match existing {
        Some(prev) if prev.as_slice() == new_key_bytes.as_ref() => IdentityChange::NewOrUnchanged,
        Some(_) => IdentityChange::ReplacedExisting,
        None => IdentityChange::NewOrUnchanged,
    })
}

async fn is_trusted_identity_impl(
    inner: &TxRef,
    address: &ProtocolAddress,
    identity: &IdentityKey,
) -> Result<bool, SignalProtocolError> {
    trace!("TxStore::is_trusted_identity: address={}", address);
    let mut guard = inner.lock().await;
    let tx = guard.as_mut().ok_or_else(tx_drained)?;
    let row = sqlx::query("SELECT key FROM identities WHERE address = ?")
        .bind(address.to_string())
        .fetch_optional(&mut **tx)
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

async fn get_identity_impl(
    inner: &TxRef,
    address: &ProtocolAddress,
) -> Result<Option<IdentityKey>, SignalProtocolError> {
    trace!("TxStore::get_identity: address={}", address);
    let mut guard = inner.lock().await;
    let tx = guard.as_mut().ok_or_else(tx_drained)?;
    let row = sqlx::query("SELECT key FROM identities WHERE address = ?")
        .bind(address.to_string())
        .fetch_optional(&mut **tx)
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
impl IdentityKeyStore for TxIdentityStore {
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
impl IdentityKeyStore for TxStore {
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

async fn get_pre_key_impl(inner: &TxRef, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
    let id: u32 = prekey_id.into();
    trace!("TxStore::get_pre_key: id={}", id);
    let mut guard = inner.lock().await;
    let tx = guard.as_mut().ok_or_else(tx_drained)?;
    let row = sqlx::query("SELECT record FROM prekeys WHERE id = ?")
        .bind(id as i64)
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_sqlx)?
        .ok_or(SignalProtocolError::InvalidPreKeyId)?;
    let bytes = row.get::<Vec<u8>, _>("record");
    PreKeyRecord::deserialize(&bytes)
}

async fn save_pre_key_impl(
    inner: &TxRef,
    prekey_id: PreKeyId,
    record: &PreKeyRecord,
) -> Result<(), SignalProtocolError> {
    let id: u32 = prekey_id.into();
    debug!("TxStore::save_pre_key: id={}", id);
    let bytes = record.serialize()?;
    let mut guard = inner.lock().await;
    let tx = guard.as_mut().ok_or_else(tx_drained)?;
    sqlx::query("INSERT OR REPLACE INTO prekeys (id, record) VALUES (?, ?)")
        .bind(id as i64)
        .bind(bytes)
        .execute(&mut **tx)
        .await
        .map_err(map_sqlx)?;
    Ok(())
}

async fn remove_pre_key_impl(inner: &TxRef, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
    let id: u32 = prekey_id.into();
    debug!("TxStore::remove_pre_key: id={}", id);
    let mut guard = inner.lock().await;
    let tx = guard.as_mut().ok_or_else(tx_drained)?;
    sqlx::query("DELETE FROM prekeys WHERE id = ?")
        .bind(id as i64)
        .execute(&mut **tx)
        .await
        .map_err(map_sqlx)?;
    Ok(())
}

#[async_trait(?Send)]
impl PreKeyStore for TxPreKeyStore {
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
impl PreKeyStore for TxStore {
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

async fn get_signed_pre_key_impl(
    inner: &TxRef,
    signed_prekey_id: SignedPreKeyId,
) -> Result<SignedPreKeyRecord, SignalProtocolError> {
    let id: u32 = signed_prekey_id.into();
    trace!("TxStore::get_signed_pre_key: id={}", id);
    let mut guard = inner.lock().await;
    let tx = guard.as_mut().ok_or_else(tx_drained)?;
    let row = sqlx::query("SELECT record FROM signed_prekeys WHERE id = ?")
        .bind(id as i64)
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_sqlx)?
        .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?;
    let bytes = row.get::<Vec<u8>, _>("record");
    SignedPreKeyRecord::deserialize(&bytes)
}

async fn save_signed_pre_key_impl(
    inner: &TxRef,
    signed_prekey_id: SignedPreKeyId,
    record: &SignedPreKeyRecord,
) -> Result<(), SignalProtocolError> {
    let id: u32 = signed_prekey_id.into();
    debug!("TxStore::save_signed_pre_key: id={}", id);
    let bytes = record.serialize()?;
    let mut guard = inner.lock().await;
    let tx = guard.as_mut().ok_or_else(tx_drained)?;
    sqlx::query("INSERT OR REPLACE INTO signed_prekeys (id, record) VALUES (?, ?)")
        .bind(id as i64)
        .bind(bytes)
        .execute(&mut **tx)
        .await
        .map_err(map_sqlx)?;
    Ok(())
}

#[async_trait(?Send)]
impl SignedPreKeyStore for TxSignedPreKeyStore {
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
impl SignedPreKeyStore for TxStore {
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

async fn get_kyber_pre_key_impl(
    inner: &TxRef,
    kyber_prekey_id: KyberPreKeyId,
) -> Result<KyberPreKeyRecord, SignalProtocolError> {
    let id: u32 = kyber_prekey_id.into();
    trace!("TxStore::get_kyber_pre_key: id={}", id);
    let mut guard = inner.lock().await;
    let tx = guard.as_mut().ok_or_else(tx_drained)?;
    let row = sqlx::query("SELECT record FROM kyber_prekeys WHERE id = ?")
        .bind(id as i64)
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_sqlx)?
        .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?;
    let bytes = row.get::<Vec<u8>, _>("record");
    KyberPreKeyRecord::deserialize(&bytes)
}

async fn save_kyber_pre_key_impl(
    inner: &TxRef,
    kyber_prekey_id: KyberPreKeyId,
    record: &KyberPreKeyRecord,
) -> Result<(), SignalProtocolError> {
    let id: u32 = kyber_prekey_id.into();
    debug!("TxStore::save_kyber_pre_key: id={}", id);
    let bytes = record.serialize()?;
    let mut guard = inner.lock().await;
    let tx = guard.as_mut().ok_or_else(tx_drained)?;
    sqlx::query("INSERT OR REPLACE INTO kyber_prekeys (id, record, used) VALUES (?, ?, 0)")
        .bind(id as i64)
        .bind(bytes)
        .execute(&mut **tx)
        .await
        .map_err(map_sqlx)?;
    Ok(())
}

async fn mark_kyber_pre_key_used_impl(
    inner: &TxRef,
    kyber_prekey_id: KyberPreKeyId,
) -> Result<(), SignalProtocolError> {
    let id: u32 = kyber_prekey_id.into();
    debug!("TxStore::mark_kyber_pre_key_used: id={}", id);
    let mut guard = inner.lock().await;
    let tx = guard.as_mut().ok_or_else(tx_drained)?;
    sqlx::query("DELETE FROM kyber_prekeys WHERE id = ?")
        .bind(id as i64)
        .execute(&mut **tx)
        .await
        .map_err(map_sqlx)?;
    Ok(())
}

#[async_trait(?Send)]
impl KyberPreKeyStore for TxKyberPreKeyStore {
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
impl KyberPreKeyStore for TxStore {
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
