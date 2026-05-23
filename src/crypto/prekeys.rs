//! Prekey lifecycle helpers — generate batches, upload them to Signal's
//! keyserver, persist locally.
//!
//! ## Ordering — local-transactional persist+upload
//!
//! signal-cli's `PreKeyHelper.refreshPreKeys` uploads first and writes
//! locally on success. That order eliminates the "local row exists but
//! server doesn't" hole at the cost of opening a different one: if the
//! local write fails *after* a successful upload, the server hands out
//! prekeys we can't fulfill (peers initiate PreKey sessions against
//! IDs we don't have private halves for, decrypt fails, messages drop).
//!
//! We close both holes with a local transaction:
//!
//! 1. `generate_batch` produces records in memory (no I/O beyond
//!    reading the identity keypair once).
//! 2. Pre-fetch upload credentials so the upload path never re-enters
//!    the connection pool while the transaction holds it.
//! 3. `pool.begin()` opens a transaction; `persist_batch_in_tx` writes
//!    the records inside it.
//! 4. `upload_keys_for_identity` issues the keys PUT.
//! 5. On upload success: `tx.commit()`. On any earlier failure: drop
//!    `TxStore`, sqlx rolls the transaction back, local store unchanged.
//!
//! Only the `tx.commit()` step itself can produce a server-vs-local
//! mismatch (disk full, fsync error after a successful upload); that's
//! a strictly narrower window than either of the simpler orderings.

use libsignal_protocol::{
    GenericSignedPreKey, KeyPair, KyberPreKeyRecord, PreKeyId, PreKeyRecord, PreKeyStore, SignalProtocolError,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, Timestamp, kem,
};
use log::{debug, info};
use thiserror::Error;

use crate::SqliteStore;
use crate::storage::Store;

/// Watermark below which the replenishment task generates a new batch.
/// Signal's clients use ~100 as the default lower bound; we mirror.
pub const PREKEY_LOW_WATERMARK: u32 = 25;

/// Number of one-time prekeys generated per replenishment batch.
pub const PREKEY_BATCH_SIZE: u32 = 100;

/// Which Signal identity a prekey batch belongs to. Signal accounts
/// carry two: the ACI (account identifier UUID) and the PNI (phone-
/// number identifier UUID). Each identity has its own keypair and its
/// own prekey pool on the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityKind {
    Aci,
    Pni,
}

impl IdentityKind {
    /// URL query-param value (`?identity=aci` vs `?identity=pni`).
    pub fn as_query_param(self) -> &'static str {
        match self {
            IdentityKind::Aci => "aci",
            IdentityKind::Pni => "pni",
        }
    }
}

#[derive(Error, Debug)]
pub enum PrekeyError {
    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StoreError),

    #[error("libsignal-protocol error: {0}")]
    Signal(#[from] SignalProtocolError),

    #[error("storage error during upload: {0}")]
    Store(crate::storage::StoreError),

    #[error("prekey upload failed: {0}")]
    Upload(String),
}

/// A freshly generated prekey batch. Holds the records in memory plus
/// the IDs they were assigned. Created by [`generate_batch`]; consumed
/// by [`upload_batch`] (sends to the server) and [`persist_batch`]
/// (writes to local SQLite).
#[derive(Debug)]
pub struct GeneratedBatch {
    pub one_time_records: Vec<PreKeyRecord>,
    pub signed_record: SignedPreKeyRecord,
    pub kyber_record: KyberPreKeyRecord,
    pub one_time_prekey_ids: Vec<u32>,
    pub signed_prekey_id: u32,
    pub kyber_prekey_id: u32,
}

/// Generate a fresh batch of prekeys in memory for the given identity.
/// Does NOT write to the store. The identity's private half signs the
/// signed-prekey and kyber-prekey. IDs start at `next_id` and increase
/// monotonically.
pub async fn generate_batch<R: rand::Rng + rand::CryptoRng>(
    rng: &mut R,
    store: &SqliteStore,
    identity_kind: IdentityKind,
    next_id: u32,
) -> Result<GeneratedBatch, PrekeyError> {
    debug!(
        "generate_batch: identity={:?} next_id={} batch_size={}",
        identity_kind, next_id, PREKEY_BATCH_SIZE
    );

    let identity_keypair = match identity_kind {
        IdentityKind::Aci => store.load_identity().await?.identity_keypair,
        IdentityKind::Pni => store
            .get_pni_identity_keypair()
            .await?
            .ok_or_else(|| PrekeyError::Storage(crate::storage::StoreError::NotLinked))?,
    };
    let signing_key = identity_keypair.private_key();

    // One-time prekeys
    let mut one_time_records = Vec::with_capacity(PREKEY_BATCH_SIZE as usize);
    let mut one_time_ids = Vec::with_capacity(PREKEY_BATCH_SIZE as usize);
    for i in 0..PREKEY_BATCH_SIZE {
        let id_u32 = next_id + i;
        let id = PreKeyId::from(id_u32);
        let kp = KeyPair::generate(rng);
        one_time_records.push(PreKeyRecord::new(id, &kp));
        one_time_ids.push(id_u32);
    }

    // Signed prekey
    let signed_id_u32 = next_id + PREKEY_BATCH_SIZE;
    let signed_id = SignedPreKeyId::from(signed_id_u32);
    let signed_kp = KeyPair::generate(rng);
    let signed_pub = signed_kp.public_key.serialize();
    let signature = signing_key.calculate_signature(&signed_pub, rng).map_err(|e| {
        PrekeyError::Signal(SignalProtocolError::InvalidArgument(format!(
            "signed prekey signature: {e}"
        )))
    })?;
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let signed_record = SignedPreKeyRecord::new(
        signed_id,
        Timestamp::from_epoch_millis(timestamp_ms),
        &signed_kp,
        &signature,
    );

    // Kyber (PQXDH) prekey
    let kyber_id_u32 = next_id + PREKEY_BATCH_SIZE + 1;
    let kyber_id = libsignal_protocol::KyberPreKeyId::from(kyber_id_u32);
    let kyber_record = KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, kyber_id, signing_key)?;

    info!(
        "generate_batch: produced {} one-time + 1 signed + 1 kyber prekey (in memory)",
        PREKEY_BATCH_SIZE
    );

    Ok(GeneratedBatch {
        one_time_records,
        signed_record,
        kyber_record,
        one_time_prekey_ids: one_time_ids,
        signed_prekey_id: signed_id_u32,
        kyber_prekey_id: kyber_id_u32,
    })
}

/// Persist a generated batch to the local SQLite store via the
/// pool-backed `SqliteStore`. Each save is its own atomic SQL op; the
/// batch as a whole is not transactional. Prefer
/// [`persist_batch_in_tx`] for the upload-or-rollback path.
pub async fn persist_batch(store: &SqliteStore, batch: &GeneratedBatch) -> Result<(), PrekeyError> {
    debug!(
        "persist_batch: writing {} one-time + 1 signed + 1 kyber prekey to local store",
        batch.one_time_records.len()
    );

    for (idx, record) in batch.one_time_records.iter().enumerate() {
        let id = PreKeyId::from(batch.one_time_prekey_ids[idx]);
        let mut store_mut = store.clone();
        PreKeyStore::save_pre_key(&mut store_mut, id, record).await?;
    }

    let mut store_mut = store.clone();
    SignedPreKeyStore::save_signed_pre_key(
        &mut store_mut,
        SignedPreKeyId::from(batch.signed_prekey_id),
        &batch.signed_record,
    )
    .await?;

    let mut store_mut = store.clone();
    libsignal_protocol::KyberPreKeyStore::save_kyber_pre_key(
        &mut store_mut,
        libsignal_protocol::KyberPreKeyId::from(batch.kyber_prekey_id),
        &batch.kyber_record,
    )
    .await?;

    Ok(())
}

/// Persist a generated batch inside the given [`TxStore`]'s in-flight
/// transaction. Used by [`generate_upload_persist`] so that an upload
/// failure or a commit failure rolls back the prekey writes
/// atomically, preventing the "server has prekeys but local DB
/// doesn't" failure mode the Architect flagged.
async fn persist_batch_in_tx(
    tx_store: &crate::storage::tx::TxStore,
    batch: &GeneratedBatch,
) -> Result<(), PrekeyError> {
    debug!(
        "persist_batch_in_tx: writing {} one-time + 1 signed + 1 kyber prekey inside transaction",
        batch.one_time_records.len()
    );

    let mut pre_key = tx_store.pre_key_store();
    let mut signed = tx_store.signed_pre_key_store();
    let mut kyber = tx_store.kyber_pre_key_store();

    for (idx, record) in batch.one_time_records.iter().enumerate() {
        let id = PreKeyId::from(batch.one_time_prekey_ids[idx]);
        PreKeyStore::save_pre_key(&mut pre_key, id, record).await?;
    }
    SignedPreKeyStore::save_signed_pre_key(
        &mut signed,
        SignedPreKeyId::from(batch.signed_prekey_id),
        &batch.signed_record,
    )
    .await?;
    libsignal_protocol::KyberPreKeyStore::save_kyber_pre_key(
        &mut kyber,
        libsignal_protocol::KyberPreKeyId::from(batch.kyber_prekey_id),
        &batch.kyber_record,
    )
    .await?;
    Ok(())
}

/// Upload a generated batch to Signal's keyserver under the given
/// identity. Convenience wrapper that loads credentials from the store
/// and then dispatches. Callers that need to interleave upload with an
/// open transaction should call [`crate::api::load_upload_credentials`]
/// up-front and then [`crate::api::upload_keys_for_identity`] directly.
pub async fn upload_batch(
    store: &SqliteStore,
    batch: &GeneratedBatch,
    identity_kind: IdentityKind,
) -> Result<(), PrekeyError> {
    log::debug!("upload_batch: identity={identity_kind:?}");
    let creds = crate::api::load_upload_credentials(store, identity_kind)
        .await
        .map_err(api_to_prekey)?;
    crate::api::upload_keys_for_identity(&creds, batch, identity_kind)
        .await
        .map_err(api_to_prekey)
}

fn api_to_prekey(e: crate::api::ApiError) -> PrekeyError {
    match e {
        crate::api::ApiError::Storage(s) => PrekeyError::Store(s),
        other => PrekeyError::Upload(other.to_string()),
    }
}

/// Orchestrator for a full prekey refresh: generate records in memory,
/// persist them inside a local sqlx transaction, upload to the server,
/// and commit only if the upload succeeds.
///
/// **Rationale** (Architect round 3): signal-cli's order is
/// "upload-then-persist," which assumes local writes never fail. If a
/// local write fails *after* the upload succeeded, Signal's server
/// hands out prekeys we can't fulfill, peers establish PreKey sessions
/// against IDs we don't have the private halves for, and inbound
/// messages fail to decrypt — a permanent message-loss hole. The
/// transactional persist+upload flow eliminates that hole:
///
/// - persist fails before upload  -> rollback, no upload attempted
/// - upload fails after persist   -> rollback, no orphan rows
/// - upload + commit both succeed -> server and local state agree
///
/// The only remaining failure mode is `tx.commit()` itself failing
/// after a successful upload (sqlite commit is a single write-ahead
/// barrier flush; failures are rare and indicate disk/filesystem
/// trouble). We surface that as an error rather than silently
/// proceeding.
pub async fn generate_upload_persist<R: rand::Rng + rand::CryptoRng>(
    rng: &mut R,
    store: &SqliteStore,
    identity_kind: IdentityKind,
    next_id: u32,
) -> Result<GeneratedBatch, PrekeyError> {
    // 1. Generate the records in memory.
    let batch = generate_batch(rng, store, identity_kind, next_id).await?;

    // 2. Read upload credentials BEFORE opening the transaction. The
    //    upload path must not touch the connection pool while the
    //    transaction holds a connection (in `:memory:` test stores
    //    with pool_size=1 this would deadlock; in production it
    //    would just stall and time out).
    let creds = crate::api::load_upload_credentials(store, identity_kind)
        .await
        .map_err(api_to_prekey)?;

    // 3. Open a local transaction and write the records inside it.
    let pool = store.pool().clone();
    let tx = pool.begin().await.map_err(crate::storage::StoreError::from)?;
    let tx_store = crate::storage::tx::TxStore::new(tx);
    persist_batch_in_tx(&tx_store, &batch).await?;

    // 4. Attempt the upload using the pre-fetched credentials. No
    //    store access here — safe even though the tx still holds a
    //    connection. On failure, `tx_store` drops at the end of this
    //    scope and sqlx rolls back the transaction.
    crate::api::upload_keys_for_identity(&creds, &batch, identity_kind)
        .await
        .map_err(api_to_prekey)?;

    // 5. Upload succeeded. Commit the transaction. The only remaining
    //    failure mode is `tx.commit()` itself failing (disk full,
    //    fsync error) — at that point the server believes we have
    //    prekeys we don't. Surface the error so the caller can decide
    //    how to handle the inconsistency.
    tx_store
        .commit()
        .await
        .map_err(|e| PrekeyError::Storage(crate::storage::StoreError::Sqlx(e)))?;

    Ok(batch)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
