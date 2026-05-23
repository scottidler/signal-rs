//! Prekey lifecycle helpers — generate batches, upload them to Signal's
//! keyserver, then persist locally.
//!
//! The order matters: signal-cli's `PreKeyHelper.refreshPreKeys` uploads
//! first and only writes to the local store on success. This module
//! mirrors that ordering so a failed upload cannot leave orphan prekeys
//! in the local DB that the server doesn't know about.

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

/// Generate a fresh batch of prekeys in memory. Does NOT write to the
/// store. The identity-key's private half signs the signed-prekey and
/// kyber-prekey. IDs start at `next_id` and increase monotonically.
pub async fn generate_batch<R: rand::Rng + rand::CryptoRng>(
    rng: &mut R,
    store: &SqliteStore,
    next_id: u32,
) -> Result<GeneratedBatch, PrekeyError> {
    debug!("generate_batch: next_id={} batch_size={}", next_id, PREKEY_BATCH_SIZE);

    let identity = store.load_identity().await?;
    let signing_key = identity.identity_keypair.private_key();

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

/// Persist a generated batch to the local SQLite store. Call ONLY after
/// [`upload_batch`] succeeds — signal-cli's order — so a failed upload
/// cannot leave orphan prekeys in the local DB.
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

/// Upload a generated batch to Signal's keyserver. Reads credentials
/// (aci, password, device_id, identity keypair) from the store but
/// reads the prekey records from `batch` (in memory) — does NOT touch
/// the prekey tables.
pub async fn upload_batch(store: &SqliteStore, batch: &GeneratedBatch) -> Result<(), PrekeyError> {
    log::debug!("upload_batch: dispatching to api::upload_keys_for_aci");
    crate::api::upload_keys_for_aci(store, batch)
        .await
        .map_err(|e| match e {
            crate::api::ApiError::Storage(s) => PrekeyError::Store(s),
            other => PrekeyError::Upload(other.to_string()),
        })
}

/// Convenience orchestrator matching signal-cli's ordering: generate
/// records in memory, upload to the server, then — only on upload
/// success — persist to the local store.
pub async fn generate_upload_persist<R: rand::Rng + rand::CryptoRng>(
    rng: &mut R,
    store: &SqliteStore,
    next_id: u32,
) -> Result<GeneratedBatch, PrekeyError> {
    let batch = generate_batch(rng, store, next_id).await?;
    upload_batch(store, &batch).await?;
    persist_batch(store, &batch).await?;
    Ok(batch)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
