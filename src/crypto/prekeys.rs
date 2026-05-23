//! Prekey lifecycle helpers - generate batches, persist via the
//! libsignal-protocol storage traits on [`crate::SqliteStore`].
//!
//! The "upload to Signal's keyserver" half of the lifecycle lives in
//! Phase 10 (it needs `libsignal-net-chat`'s auth-key endpoints
//! against a live Signal account). What this module ships is the
//! generation + local persistence, which is testable now.

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

    #[error(
        "prekey upload to Signal's keyserver is not yet wired; \
         Phase 10 wires libsignal-net-chat's keys endpoint"
    )]
    UploadNotImplemented,
}

/// Output of a single prekey-generation pass: the IDs assigned to each
/// new prekey. Phase 10's upload task takes the matching records back
/// out of the store and pushes them to Signal's keyserver.
#[derive(Debug, Clone)]
pub struct GeneratedBatch {
    pub one_time_prekey_ids: Vec<u32>,
    pub signed_prekey_id: u32,
    pub kyber_prekey_id: u32,
}

/// Generate and persist a fresh prekey batch. Uses the identity-key's
/// private half to sign the new signed-prekey and kyber-prekey records.
/// Assigns IDs starting at `next_id` to keep them monotonically
/// increasing across replenishments.
pub async fn generate_and_persist_batch<R: rand::Rng + rand::CryptoRng>(
    rng: &mut R,
    store: &SqliteStore,
    next_id: u32,
) -> Result<GeneratedBatch, PrekeyError> {
    debug!(
        "generate_and_persist_batch: next_id={} batch_size={}",
        next_id, PREKEY_BATCH_SIZE
    );

    let identity = store.load_identity().await?;
    let signing_key = identity.identity_keypair.private_key();

    // One-time prekeys: PREKEY_BATCH_SIZE of them.
    let mut one_time_ids = Vec::with_capacity(PREKEY_BATCH_SIZE as usize);
    for i in 0..PREKEY_BATCH_SIZE {
        let id_u32 = next_id + i;
        let id = PreKeyId::from(id_u32);
        let kp = KeyPair::generate(rng);
        let record = PreKeyRecord::new(id, &kp);
        let mut store_mut = store.clone();
        PreKeyStore::save_pre_key(&mut store_mut, id, &record).await?;
        one_time_ids.push(id_u32);
    }

    // Signed prekey - one per batch. Signs the new key with the
    // identity private key.
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
    let mut store_mut = store.clone();
    SignedPreKeyStore::save_signed_pre_key(&mut store_mut, signed_id, &signed_record).await?;

    // Kyber (PQXDH) prekey - one per batch.
    let kyber_id_u32 = next_id + PREKEY_BATCH_SIZE + 1;
    let kyber_id = libsignal_protocol::KyberPreKeyId::from(kyber_id_u32);
    let kyber_record = KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, kyber_id, signing_key)?;
    let mut store_mut = store.clone();
    libsignal_protocol::KyberPreKeyStore::save_kyber_pre_key(&mut store_mut, kyber_id, &kyber_record).await?;

    info!(
        "generate_and_persist_batch: persisted {} one-time + 1 signed + 1 kyber prekey",
        PREKEY_BATCH_SIZE
    );

    Ok(GeneratedBatch {
        one_time_prekey_ids: one_time_ids,
        signed_prekey_id: signed_id_u32,
        kyber_prekey_id: kyber_id_u32,
    })
}

/// Upload a generated batch to Signal's keyserver. Currently returns
/// `PrekeyError::UploadNotImplemented`; Phase 10 wires this to
/// `libsignal-net-chat`'s `set_pre_keys` (or equivalent) endpoint.
pub async fn upload_batch(_: &SqliteStore, _: &GeneratedBatch) -> Result<(), PrekeyError> {
    log::warn!("upload_batch: live upload is Phase 10");
    Err(PrekeyError::UploadNotImplemented)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
